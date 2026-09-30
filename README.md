# DCSync & DCShadow Prevention Lab (`DCSync-DCShadow-Prevention-Lab`)

Layered defense against both Active Directory credential-replication attacks — **DCSync** (dump every credential via `IDL_DRSGetNCChanges`, opnum 3) and **DCShadow** (register a rogue DC and push arbitrary attribute changes via `IDL_DRSReplicaAdd`, opnum 5) — built and validated end-to-end in a live lab.

Both attacks abuse the legitimate MS-DRSR replication protocol at the same UUID (`e3514235-4b06-11d1-ab04-00c04fc2dcd2`). The defense treats them as one problem — every layer that stops DCSync also stops DCShadow, because both are gated on the same interface/opnum/SID discriminators.

This repo bundles:

- Four documents (see [docs/](docs/)) covering the design, step-by-step build, technical explainer, and a complete guide with proof-of-concept results.
- A modified copy of the Zero Networks RPC Firewall (see [rpcfirewall/](rpcfirewall/)) with an added payload-layer DRS request-inspection module.
- The dsinternals DCFWTool (see [DCFWTool/](DCFWTool/)) with a ready-to-use `lab.local` config.
- Test scripts (see [scripts/](scripts/)) — most importantly the transport-isolation harness used to identify the local-SYSTEM ncalrpc bypass.

## Quick start

If you're building the whole stack: read [docs/DCSync-Prevention-Explained.md](docs/DCSync-Prevention-Explained.md) first (5 minutes), then follow [docs/DCSync-Hardening-Clean-StepByStep.md](docs/DCSync-Hardening-Clean-StepByStep.md).

If you're reproducing the lab exactly as we built it, use [REPRODUCE-LAB.md](REPRODUCE-LAB.md).

If you want the full context — rationale, safety notes, code changes, PoC results — read [docs/DCSync-Prevention-Complete-Guide.md](docs/DCSync-Prevention-Complete-Guide.md).

## Repository layout

```
DCSync-DCShadow-Prevention-Lab/
├── README.md                  ← this file
├── LICENSE                    ← MIT for our contributions
├── NOTICE                     ← attribution for bundled upstream projects
├── CHANGES-TO-UPSTREAM.md     ← exact list of what we changed in rpcfirewall
├── REPRODUCE-LAB.md           ← step-by-step lab reproduction guide
├── .gitignore
│
├── docs/                      ← reference documentation
│   ├── DCSync-Prevention-Explained.md         (why it works, 5-min read)
│   ├── DCSync-Hardening-Clean-StepByStep.md   (what to run, terse)
│   ├── DCSync-Hardening-Runbook.md            (runbook + Fixes log)
│   └── DCSync-Prevention-Complete-Guide.md    (definitive combined reference)
│
├── scripts/                   ← helper scripts we wrote
│   └── Test-DcsyncTransports.ps1              (transport isolation harness)
│
├── patches/                   ← diffs and reference config for upstream modifications
│   └── (see CHANGES-TO-UPSTREAM.md for content)
│
├── rpcfirewall/               ← modified fork of zeronetworks/rpcfirewall
│   ├── (upstream code, license preserved)
│   ├── rpcFirewall/drsCapture.hpp             ← NEW: our capture shim
│   ├── rpcFirewall/drsCapture.cpp             ← NEW: our capture shim impl
│   ├── rpcFirewall/drsInspect.hpp             ← NEW: our inspector
│   ├── rpcFirewall/drsInspect.cpp             ← NEW: our inspector impl
│   ├── rpcFirewall/dllmain.cpp                ← MODIFIED: 4 wire-in points
│   └── scripts/Deploy-DrsHarden.ps1           ← NEW: deployment helper
│
└── DCFWTool/                  ← MichaelGrafnetter/active-directory-firewall
    ├── (upstream code, license preserved)
    └── Set-ADDSFirewallPolicy.json            ← ADDED: lab.local config
```

## What we built vs what's upstream

See [CHANGES-TO-UPSTREAM.md](CHANGES-TO-UPSTREAM.md) for the precise list of new files and the exact edits to `dllmain.cpp`. The upstream projects' licenses and attribution are preserved in [NOTICE](NOTICE) and inside each subfolder.

## Environment this was built in

- Domain: `lab.local`
- Two DCs: DC (`192.168.20.1`), DC2 (`192.168.20.2`)
- Client subnet: `192.168.20.0/24`
- Attacker: Kali at `192.168.20.50`
- One SQL member at `192.168.20.30`

Adjust to your own environment before running any of the commands. The scripts and configs are labeled where changes are required.

## The one thing this repo does not solve

Cross-DC mimikatz-as-SYSTEM DCSync/DCShadow (attacker on DC1 authenticating outbound to DC2 as its own machine account via Kerberos). The wire is byte-identical to legitimate KCC replication for opnum 3, and opnum 5 registration under a real DC identity would look the same. WDAC (kernel code-integrity) is the mitigation for this specific case and is documented as Phase 8 in the runbook but not built here yet.

## Attacks covered vs mitigations

| Attack | Wire fingerprint | Mitigation layer in this repo |
|---|---|---|
| DCSync from any non-DC identity (Kali, DA user) | DRSUAPI opnum 3, non-`S-1-5-9` caller | RPC Firewall base rule (Phase 6) |
| DCShadow from any non-DC identity | DRSUAPI opnum 5, non-`S-1-5-9` caller | RPC Firewall base rule (Phase 6) |
| Targeted single-object DCSync from a non-partner source | opnum 3, `partner=0`, DN starts `CN=` | DRS Request-Inspection module (Phase 7 DETECT) |
| Coercion primitives (PetitPotam, DFSCoerce, PrinterBug) | MS-EFSR / MS-DFSNM / MS-RPRN interfaces | RPC filters (Phase 4/6) |
| Local mimikatz-as-SYSTEM DCSync (ncalrpc) | opnum 3, primary SID S-1-5-18, ncalrpc | Optional: netsh RPC filter with SDDL condition |
| Cross-DC mimikatz-as-SYSTEM DCSync/DCShadow | Byte-identical to legit KCC | **Not closed here** — Phase 8 (WDAC) |

## License

MIT for our contributions. Upstream projects retain their original licenses (see [NOTICE](NOTICE) and the LICENSE files inside `rpcfirewall/` and `DCFWTool/`).
