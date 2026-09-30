# DCSync Prevention — How Our Stack Actually Works

A brief technical explainer of the defense we built: what DCSync does at the wire, how each layer intercepts it, how we identified attacker vs legitimate replication by observation, and how we closed the SYSTEM-privilege case.

## What DCSync is at the wire

DCSync is not an exploit — it's a *legitimate* Active Directory protocol used the wrong way.

- **Protocol:** MS-DRSR (Directory Replication Service Remote Protocol), UUID `e3514235-4b06-11d1-ab04-00c04fc2dcd2`, over MSRPC.
- **Endpoint:** `lsass.exe` on every DC hosts the DRSUAPI RPC server.
- **The two important opnums:**
  - `IDL_DRSGetNCChanges` (opnum 3) — "pull replication changes for this partition, including credential attributes." This is what mimikatz `lsadump::dcsync` calls.
  - `IDL_DRSReplicaAdd` (opnum 5) — "register me as a replication partner." This is what mimikatz `lsadump::dcshadow` calls.
- **Authorization:** at the raw AD level, holding the `DS-Replication-Get-Changes-All` extended right lets you invoke these successfully. Members of Domain Admins, Enterprise Admins, and the built-in Administrators group inherit it. So does anyone an attacker convinces AD to grant it to.

At the wire, a `GetNCChanges` request from mimikatz is byte-similar to one from a real domain controller doing scheduled replication. Both include the same interface UUID, the same opnum, the same DRSUAPI protocol version, and the same authentication style (Kerberos, `PKT_PRIVACY`). That's the fundamental difficulty.

## Why AD ACL alone isn't enough

The default ACL is correct — only DCs and admins hold the replication rights. But an attacker who compromises any DA-equivalent identity inherits those rights immediately, and from that point onward every AD access check says "yes." No amount of ACL tightening helps against a legitimately-authenticated caller.

We need controls that operate **below the AD access check** — at the RPC layer where the DsGetNCChanges call arrives on the DC, before NTDS ever evaluates permissions.

## The layered defense — what each phase actually does

Reading top to bottom, each layer intercepts a different attack shape:

| Layer | Where it lives | What it inspects | What it stops |
|---|---|---|---|
| **AD ACL + SACL + OWNER RIGHTS + honeytoken** | AD security descriptor on the NC | Which principals hold `Get-Changes*` | Non-standard grants; produces detection signal (4662) for successful use |
| **Tier-0 silo** | Kerberos KDC (with FAST armoring) | Where privileged users can log in from | Cross-tier compromise laterally reaching the DC identity |
| **Coercion filters (`netsh rpc filter`)** | Windows Filtering Platform (WFP) at the RPC UM layer | MS-EFSR / MS-DFSNM / MS-RPRN interface bindings | PetitPotam / DFSCoerce / PrinterBug — coercing a DC to auth to an attacker relay |
| **DC firewall (DCFWTool GPO)** | Windows Firewall / WFP at the packet layer | Source IPs vs DC/management/client classes | Non-legitimate reachability of RPC endpoints |
| **RPC Firewall (Zero Networks base) — Detours DLL in lsass** | Inside `lsass.exe` | Every RPC call's UUID, opnum, caller SID, source | DRSUAPI opnum 3/5 from any identity not carrying `S-1-5-9` (Enterprise Domain Controllers) |
| **DRSI (our modified DLL)** | Inside `lsass.exe`, sits above the base RPCFW | Contents of the marshalled `DRS_MSG_GETCHGREQ` buffer, partner topology, SID | Targeted single-object DCSync from non-partner sources; audit signal for the ceiling case |
| **Optional: ncalrpc SYSTEM filter** | WFP RPC filter layer | DRSUAPI over ncalrpc + primary SID = S-1-5-18 | mimikatz-as-SYSTEM DCSync via local RPC (the on-DC bypass) |
| **Future: WDAC** | Kernel code-integrity | Which binaries are allowed to execute | mimikatz.exe (or any non-approved binary) launching at all |

Each layer is orthogonal — none of them relies on any other to be correct.

## How the RPC hook actually works

The Zero Networks base and our modifications both work by injecting a DLL into `lsass.exe` at startup and using Microsoft Detours to hook the internal `rpcrt4.dll` functions that dispatch server-side RPC calls. There are six:

- `NdrStubCall2`
- `NdrServerCallAll`
- `NdrAsyncServerCall`
- `Ndr64AsyncServerCallAll`
- `Ndr64AsyncServerCall64`
- `NdrServerCallNdr64`

Every one of them, before invoking the real server routine, gives the hook a `PRPC_MESSAGE *pRpcMsg`. From that plus a couple of runtime queries we get:

- Interface UUID (from `pRpcMsg->RpcInterfaceInformation`)
- Opnum (`pRpcMsg->ProcNum`)
- The marshalled request buffer + length (`pRpcMsg->Buffer`, `pRpcMsg->BufferLength`)
- Caller SID (via `RpcBindingInqAuthClient`)
- Auth level and auth service (Kerberos / NTLM / Anonymous)
- Source IP + port (via `I_RpcServerInqRemoteConnAddress`)

Our decision logic sees all of this before the real DRSUAPI function ever executes. If we decide to block, we call `RpcRaiseException(ERROR_ACCESS_DENIED)` and the caller gets `rpc_s_access_denied` (0x5). If we allow, we return and the original dispatch continues.

Where this hook does NOT run:

- The base build early-returns when the binding string contains `ncalrpc` (local RPC). That was the on-DC-SYSTEM bypass we later closed with a separate RPC-filter-layer rule.
- It doesn't intercept client-side RPC (calls originating from lsass to other DCs).

## How we told legitimate replication apart from attacks

We didn't guess. We captured actual RPC buffers and compared them. The Phase 1 capture shim in the DLL writes a bounded, SEH-safe copy of every DRSUAPI opnum 3 (and later, opnum 0) request buffer to disk, tagged with source IP, caller SID, and opnum in a `manifest.csv` file. That gave us the corpus.

From that corpus, four signals turned out to be discriminating:

1. **Caller SID class.** Legit KCC replication authenticates as a **DC machine account** (`DC$` / `DC2$`, SID ending in the DC computer object's RID, always inherits the `S-1-5-9` Enterprise Domain Controllers group). mimikatz DCSync run under a user token doesn't. This is the base RPCFW rule: `sid:S-1-5-9 allow, else block`.
2. **Target object shape.** Real bulk replication targets a partition NC head (DN starts with `DC=…`). mimikatz `/user:X` targets a specific principal (DN starts with `CN=`). This is our DRSI parser's `target_is_security_principal` signal.
3. **Established partner.** Legit sources match a DC we know from `Get-ADDomainController` (auto-refreshed into `partners.txt` by a scheduled task). Non-partner sources requesting a single principal = the classic DCSync fingerprint.
4. **DsBind client PID.** Our largest wire-level surprise: the `DRS_EXTENSIONS_INT.Pid` field at offset `0x40` of every DsBind request carries the *client-reported* process ID. Legit KCC calls have that PID = lsass on the source DC (stable per boot, always small). mimikatz calls carry mimikatz's own PID. A single 4-byte DWORD is a fingerprint the default binary can't hide.

Together, these give a decision tree the code implements in `drsInspect.cpp` — allow when partner and shape are normal, alert when the shape is ambiguous, block when a non-partner asks for a single principal.

## What legit tools actually do (so we don't break them)

The behavioural study wasn't only about attackers. Every hardening change also needs to leave working tools working. We verified against:

- `repadmin /showrepl`, `/replsummary`, `/syncall`
- `Get-ADDomainController`, `Get-ADReplicationPartnerMetadata`
- `dcdiag /test:Replications`
- Real DC-to-DC replication triggered by KCC on its own schedule

Behavioural findings that shaped decisions:

- Legit tools on the DC console (`repadmin /showrepl`) use DRSUAPI over **`ncalrpc`** as the current user. That's why blocking ncalrpc universally broke everything, and why we gate the ncalrpc block on primary-SID being SYSTEM specifically.
- Legit KCC replication makes DsBind + repeated GetNCChanges over a persistent binding, roughly every 60 s per partition. mimikatz opens a fresh binding, calls DsCrackNames + GetNCChanges + DsUnbind. Cadence and DsBind frequency are also discriminators, though we didn't implement cadence-based blocking (too easy to false-positive on convergence storms).
- Legit `Get-ADDomainController` doesn't go through DRSUAPI at all — it's an LDAP call. Confirming that let us rule out our filter as a suspect when other things broke.

## The SYSTEM-privilege problem, honestly

The one attack shape our RPC-layer stack can't catch at the wire is:

**mimikatz running as SYSTEM on a DC, targeting a *different* DC.**

Why:
- SYSTEM on a DC has `S-1-5-9` in its token, so the base SID rule allows it.
- Outbound network authentication from SYSTEM on a DC uses the machine account's Kerberos ticket. On the peer DC, the request arrives as `DC1$` over Kerberos — literally byte-identical to legitimate KCC replication.
- The DRS_EXTENSIONS_INT.Pid discriminator would still catch default mimikatz here, but that's a soft signal, not enforcement.

We split the SYSTEM case in two:

- **Local case** (mimikatz on DC → same DC's DRSUAPI) — uses ncalrpc. Our netsh RPC filter with `remote_user_token=D:(A;;CC;;;SY)` blocks the DsBind when the primary token is SYSTEM. Legit t0-admin tools stay working. This is the *optional advanced* step in the runbook, and we verified it survives reboot with the 5-minute repeater task.
- **Cross-DC case** — un-closable at the RPC layer. The only defense is to prevent mimikatz from executing at all, which is what **WDAC** does. It runs in the kernel, evaluates the binary's signature or hash against a policy, and terminates the process if it doesn't match. This is Phase 8, and it's the honest answer for the remaining case.

## Fingerprint of the whole defense

Layered from most-outer to most-inner, what each layer inspects and where a bypass would have to move to next:

```
Attacker on the outside network
   │
   ▼  ── Windows Firewall (DCFWTool GPO)
   │       filters by SRC IP against Client/Management/DC classes
   │       bypass: only via allowed subnets
   │
   ▼  ── netsh RPC filter — interface-level block for coercion primitives
   │       MS-EFSR, MS-DFSNM, MS-RPRN
   │       bypass: not use those interfaces
   │
   ▼  ── netsh RPC filter — DRSUAPI over ncalrpc if primary SID = SYSTEM
   │       our optional advanced step, kernel-level WFP filter
   │       bypass: don't be SYSTEM (needs machine-account cred and off-DC pivot)
   │
   ▼  ── Detours hook inside lsass.exe (rpcrt4.dll NdrServerCall*)
   │      Base RPCFW: allow DRSUAPI opnum 3/5 only if caller has S-1-5-9
   │      DRSI (our extension): further inspects buffer + partners + SID
   │      bypass: authenticate as a DC machine account (real DC, or stolen $MACHINE.ACC)
   │
   ▼  ── ntdsai.dll GetNCChanges — the real replication server
          runs the DS access check against the caller's token
          bypass: hold the DA/replication rights legitimately or by ACL abuse
```

Each arrow is a real gate. Every attack shape we care about is stopped by at least one of them. The one that isn't — cross-DC SYSTEM — needs the outermost layer we haven't built yet (WDAC), which stops the attacker before any of the above run.

## Reading order

- The **behavioural evidence** that shaped these decisions lives in the buffer capture corpus and the Fixes log entries in the main runbook.
- The **step-by-step build** is in `DCSync-Hardening-Clean-StepByStep.md`.
- The **operator troubleshooting reference** with full context is in `DCSync-Hardening-Runbook.md`.
- The **why-it-works technical detail** is this document.

## One-line summary

DCSync is legitimate replication used adversarially, so we intercept it at every layer between the network and the real replication server — Windows Firewall, RPC filter (WFP), our Detours hook in lsass, and finally the NTDS access check — using the smallest possible discriminator at each layer (source IP, then interface + protocol, then interface + caller SID + wire content, then AD ACL). The one case none of those can distinguish from legitimate replication is a compromised DC authenticating outbound as its own machine account, which needs code-integrity enforcement (WDAC) at the executable-launch layer to close.
