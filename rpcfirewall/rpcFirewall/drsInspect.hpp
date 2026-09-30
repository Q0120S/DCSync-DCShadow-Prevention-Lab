#pragma once

// DRS Request-Inspection Module (Phase 2-4 prototype - Lab Only)
//
// Given a DRSUAPI GetNCChanges (opnum 3) request that has already passed the
// existing RPC Firewall SID gate (caller is Enterprise DCs), extract features
// from the marshalled DRS_MSG_GETCHGREQ buffer, apply the decision engine,
// and return a verdict. The caller decides whether to enforce (block via
// policy.allow=false) or audit (log only).
//
// SAFETY POSTURE (non-negotiable, this is lsass on a DC):
//   * Fail-OPEN on any error, unknown shape, parse failure, SEH fault.
//   * Bounded byte-scan of the buffer only; no NDR unmarshalling.
//   * Read-only: never modifies pRpcMsg or its buffer.
//   * SEH-wrapped copy of the buffer; parsing runs against the safe copy.
//   * Audit-only by default; enforcement requires a separate sentinel file.
//
// See dcsync-prototype/DRS-Request-Inspection-Hook-Design.md §3-§5.

#include <rpc.h>
#include <rpcndr.h>
#include <string>

namespace drsinsp
{
    enum class Decision
    {
        ALLOW,   // normal replication - pass through
        ALERT,   // suspicious - log; block iff alert_blocks sentinel present
        BLOCK    // targeted DCSync signature - block if enforce
    };

    struct Verdict
    {
        Decision    decision;
        const char* reason;   // static string; never freed
    };

    // Called from processRPCCallInternal after the SID gate has been passed.
    // Never throws; never modifies pRpcMsg. Returns ALLOW on any failure so
    // that a parser bug can never take down replication.
    Verdict inspectDrsRequest(PRPC_MESSAGE pRpcMsg,
                              const std::wstring& srcAddress,
                              const std::wstring& clientSid) noexcept;

    // Called by the wire-in to decide whether the verdict should convert to a
    // policy.allow=false (block). Returns true iff the module is enabled AND
    // enforce mode is on AND (decision==BLOCK, or decision==ALERT and
    // alert_blocks is on).
    bool shouldBlock(const Verdict& v) noexcept;

    // True while C:\Hardening\capture\drsi_enabled exists (poll cached).
    bool moduleEnabled() noexcept;
}
