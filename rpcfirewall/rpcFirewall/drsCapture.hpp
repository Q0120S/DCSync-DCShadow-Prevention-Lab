#pragma once

// DRS Request-Inspection Capture Shim (Phase 1 - Lab Only)
//
// Read-only, fail-open. Copies the marshalled DRS_MSG_GETCHGREQ buffer to
// disk under C:\Hardening\capture\ so an OFFLINE parser can build a labeled
// corpus. Never modifies the buffer; never touches the response; never
// decides allow/block. Enabled iff the sentinel file
// C:\Hardening\capture\enabled exists.
//
// Contract per Phase1-Capture-Shim-Spec.md: this component must be incapable
// of blocking, and must default to inert if anything goes wrong.

#include <rpc.h>
#include <rpcndr.h>
#include <string>

namespace drscap
{
    // DRSUAPI interface UUID (lowercase, no braces) as UuidToString emits it.
    inline constexpr wchar_t DRSUAPI_UUID[]                 = L"e3514235-4b06-11d1-ab04-00c04fc2dcd2";
    inline constexpr unsigned int DRSUAPI_OPNUM_DSBIND       = 0;   // DsBind - carries DRS_EXTENSIONS_INT
    inline constexpr unsigned int DRSUAPI_OPNUM_GETNCCHANGES = 3;   // DsGetNCChanges - DCSync payload

    // Start/stop the background writer thread. Safe to call once at DLL attach
    // and once at DLL detach. Both are no-throw.
    void startCaptureThread() noexcept;
    void stopCaptureThread() noexcept;

    // Fast opnum/interface filter for the hot path. Cheap wstring compare.
    // Returns true iff the call is DRSUAPI GetNCChanges (opnum 3). Kept for
    // callers (e.g. drsInspect) that specifically need the payload-layer op.
    bool isDrsGetNCChanges(const std::wstring& uuidString, unsigned int procNum) noexcept;

    // Broader filter: DRSUAPI opnum 0 (DsBind) OR 3 (DsGetNCChanges).
    // Use this for the Phase 1 capture shim so we get both the session-
    // establishment fingerprint (DsBind's DRS_EXTENSIONS_INT) and the
    // replication request (GetNCChanges) in the corpus.
    bool isDrsuapiInteresting(const std::wstring& uuidString, unsigned int procNum) noexcept;

    // Enqueue a bounded copy of pRpcMsg->Buffer for asynchronous write.
    // The opnum is embedded in the output filename and appended to the
    // manifest so the offline analysis can filter by call type. Never
    // touches pRpcMsg after returning; never throws; never blocks the RPC
    // thread on disk I/O.
    void captureRequest(PRPC_MESSAGE pRpcMsg,
                        const std::wstring& srcAddress,
                        const std::wstring& clientSid) noexcept;
}
