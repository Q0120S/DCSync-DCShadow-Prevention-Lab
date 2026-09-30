# Changes to Upstream Projects

Precise record of what we added or modified in the bundled third-party projects, so a reviewer can audit exactly what our contributions are.

## `rpcfirewall/` — upstream `zeronetworks/rpcfirewall`

### Files ADDED (new files, entirely our code)

| Path | Purpose |
|---|---|
| `rpcFirewall/drsCapture.hpp` | Header for the DRS Request-Inspection capture shim. |
| `rpcFirewall/drsCapture.cpp` | Bounded, SEH-safe async writer that saves DRSUAPI opnum 0 (DsBind) and opnum 3 (GetNCChanges) request buffers to disk with a manifest. Sentinel-file kill switch. |
| `rpcFirewall/drsInspect.hpp` | Header for the payload-layer inspector. |
| `rpcFirewall/drsInspect.cpp` | Feature extraction from marshalled `DRS_MSG_GETCHGREQ`, partner topology lookup, classifier, per-decision structured log, three separate enforce sentinels, allowlist. |
| `scripts/Deploy-DrsHarden.ps1` | Deployment helper: creates the data directory with locked ACL, auto-populates `partners.txt` from AD, seeds `allowlist.txt`, registers a 15-minute refresh scheduled task. Idempotent. |

### Files MODIFIED (existing upstream files with surgical additions)

#### `rpcFirewall/dllmain.cpp`

Four additions, all guarded by our own kill-switch so upstream behaviour is preserved when our module is disabled:

1. **Two `#include` lines**, near the other includes:
   ```cpp
   #include "drsCapture.hpp"
   #include "drsInspect.hpp"
   ```

2. **Inside `processRPCCallInternal`**, immediately after `populateEventParameters` returns and before `getMatchingPolicy` is called:
   ```cpp
   const bool isDrsOpnum3 =
       drscap::isDrsGetNCChanges(eventParams.uuidString, pRpcMsg->ProcNum);
   if (drscap::isDrsuapiInteresting(eventParams.uuidString, pRpcMsg->ProcNum))
   {
       drscap::captureRequest(pRpcMsg, srcAddrFromConnection, eventParams.clientSID);
   }
   ```

3. **Immediately after `getMatchingPolicy` returns**, allowing our inspector to override `policy.allow` when it decides BLOCK:
   ```cpp
   if (isDrsOpnum3 && policy.allow && drsinsp::moduleEnabled())
   {
       const drsinsp::Verdict verdict =
           drsinsp::inspectDrsRequest(pRpcMsg, srcAddrFromConnection, eventParams.clientSID);
       if (drsinsp::shouldBlock(verdict))
       {
           policy.allow = false;
       }
   }
   ```

4. **DLL lifecycle** — one call at attach and one at detach:
   - In `installRpcFirewallHooks`, after Detours attach succeeds: `drscap::startCaptureThread();`
   - In `dllDetached`, before Detours detach begins: `drscap::stopCaptureThread();`

Nothing else in `dllmain.cpp` is changed.

#### `rpcFirewall/rpcFirewall.vcxproj` and `rpcFirewall/rpcFirewall.vcxproj.filters`

Registered the four new source files (`.hpp` and `.cpp` pairs) in both project files so Visual Studio builds them and displays them in Solution Explorer. No other project settings changed.

### Design constraints in our own code (non-negotiable)

Applied uniformly in `drsCapture.cpp` and `drsInspect.cpp`:

- **Read-only.** `pRpcMsg->Buffer` is only ever `memcpy`-ed from; never modified.
- **Fail-open.** Any error, parse failure, or SEH exception → no-op (capture) or ALERT verdict (inspector). Never BLOCK on uncertainty.
- **Bounded.** Copy at most 64 KB per call. Queue at most 256 items. Feature scan at most 8 KB.
- **SEH-wrapped.** The raw copy of attacker-controlled memory runs inside `__try/__except` in a `noexcept` helper function so C++ unwinding cannot collide with Windows SEH.
- **Async I/O.** RPC thread never touches disk. Owned struct pushed to a bounded queue; a background writer thread drains it.
- **Kill switch.** Sentinel files polled once per second (cached), so `Remove-Item` takes effect within 1 second.
- **Config-driven.** All paths configurable via `HKLM\SOFTWARE\Hardening\DrsInspect\DataDir`. Default is `C:\Hardening\capture` when unset.

### What was NOT changed in the upstream

- `rpcFwManager/*` — the manager EXE and its build.
- `rpcMessages/*` — event log resource DLL.
- `rpcFirewall/pch.h`, `framework.h`, `config.hpp`, `rpcWrappers.hpp`.
- Detours attach/detach logic in `dllmain.cpp`.
- `processRPCCallInternal` above our two insertion points.
- Config file format, event log formatting, verbose logging.

## `DCFWTool/` — upstream `MichaelGrafnetter/active-directory-firewall`

### Files ADDED

| Path | Purpose |
|---|---|
| `Set-ADDSFirewallPolicy.json` | Config file with `lab.local` values (both DC IPs, client subnet `192.168.20.0/24`, static ports NTDS 38901 / Netlogon 38902 / DFSR 5722, etc.). Copy of the schema-referenced sample tailored for this environment. |

### Files MODIFIED

None. The tool itself is untouched.

## Verifying the changes

To confirm nothing in upstream files was changed beyond what's documented above, you can diff against the upstream commits. For `rpcfirewall`:

```bash
git -C rpcfirewall log --oneline -n 5
git -C rpcfirewall diff <upstream-commit> -- rpcFirewall/dllmain.cpp rpcFirewall/*.vcxproj*
```

The only diffs should be the additions listed above.
