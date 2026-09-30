// DRS Request-Inspection Capture Shim (Phase 1 - Lab Only)
// See drsCapture.hpp and dcsync-prototype/Phase1-Capture-Shim-Spec.md.
//
// Design commitments enforced here:
//   * Read-only: the RPC buffer is only read via memcpy; never modified.
//   * Fail-open: every failure path is a no-op. The shim cannot block.
//   * Bounded: at most kMaxCopyBytes copied per call; queue is bounded.
//   * SEH-wrapped: the memcpy of an attacker-controlled buffer runs under
//     __try/__except so an AV inside the copy becomes a silent drop.
//   * Async: the RPC thread never touches disk. A single background thread
//     drains a bounded queue and writes files + manifest rows.
//   * Kill switch: capture is enabled only while the sentinel file exists.

#include "pch.h"
#include <windows.h>
#include "drsCapture.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace drscap
{
    // ---- Tunables ----------------------------------------------------------
    static constexpr size_t   kMaxCopyBytes    = 64 * 1024;    // bounded copy
    static constexpr size_t   kMaxQueuedItems  = 256;          // bounded queue
    static const     wchar_t  kCaptureDir[]    = L"C:\\Hardening\\capture";
    static const     wchar_t  kSentinelPath[]  = L"C:\\Hardening\\capture\\enabled";
    static const     wchar_t  kManifestPath[]  = L"C:\\Hardening\\capture\\manifest.csv";

    // ---- Enable flag cache -------------------------------------------------
    // Poll the sentinel file at most once per kEnabledCacheMs so we don't hit
    // the filesystem on every RPC. Race between poll and call is fine: this
    // is a lab tool, not a security boundary.
    static constexpr DWORD kEnabledCacheMs = 1000;
    static std::atomic<uint64_t> gEnabledLastCheckedTick{ 0 };
    static std::atomic<bool>     gEnabledCached{ false };

    static bool captureEnabled() noexcept
    {
        const uint64_t now = GetTickCount64();
        const uint64_t last = gEnabledLastCheckedTick.load(std::memory_order_relaxed);
        if (now - last < kEnabledCacheMs)
        {
            return gEnabledCached.load(std::memory_order_relaxed);
        }
        // Refresh. Racing threads may all refresh once; harmless.
        const DWORD attrs = GetFileAttributesW(kSentinelPath);
        const bool exists = (attrs != INVALID_FILE_ATTRIBUTES) &&
                            !(attrs & FILE_ATTRIBUTE_DIRECTORY);
        gEnabledCached.store(exists, std::memory_order_relaxed);
        gEnabledLastCheckedTick.store(now, std::memory_order_relaxed);
        return exists;
    }

    // ---- Item + queue ------------------------------------------------------
    struct CapturedCall
    {
        std::vector<uint8_t> buffer;      // bounded copy of pRpcMsg->Buffer
        uint32_t             origLength;  // original BufferLength (may exceed buffer.size())
        uint32_t             opnum;       // 0 = DsBind, 3 = DsGetNCChanges
        std::wstring         srcAddress;
        std::wstring         clientSid;
        std::wstring         timestampUtc; // yyyyMMddTHHmmssfff format for filename + manifest
        uint64_t             seq;
    };

    static std::mutex                            gMutex;
    static std::condition_variable               gCv;
    static std::deque<std::unique_ptr<CapturedCall>> gQueue;
    static std::atomic<bool>                     gRunning{ false };
    static std::atomic<uint64_t>                 gSeq{ 0 };
    static std::thread                           gWriterThread;

    // ---- Helpers -----------------------------------------------------------
    static std::wstring nowUtcStamp() noexcept
    {
        SYSTEMTIME st{};
        GetSystemTime(&st);
        wchar_t buf[32];
        // 20260927T134501123 — sortable, filename-safe.
        const int n = _snwprintf_s(buf, _TRUNCATE,
            L"%04u%02u%02uT%02u%02u%02u%03u",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        if (n < 0) return L"unknown";
        return std::wstring(buf);
    }

    static void ensureCaptureDir() noexcept
    {
        // Best effort. If this fails, writes will fail too and be dropped.
        CreateDirectoryW(L"C:\\Hardening", nullptr);
        CreateDirectoryW(kCaptureDir, nullptr);
    }

    // SEH-safe copy of an attacker-controlled buffer. Returns bytes copied,
    // 0 on any fault. Kept in a separate function because __try/__except
    // is incompatible with functions that require object unwinding.
    static size_t sehSafeCopy(void* dst, const void* src, size_t n) noexcept
    {
        __try
        {
            memcpy(dst, src, n);
            return n;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    static std::wstring sanitiseForFilename(const std::wstring& src) noexcept
    {
        try
        {
            std::wstring safe;
            safe.reserve(src.size());
            for (wchar_t c : src)
            {
                const bool ok = (c >= L'0' && c <= L'9') ||
                                (c >= L'a' && c <= L'z') ||
                                (c >= L'A' && c <= L'Z') ||
                                c == L'.' || c == L':' || c == L'-';
                safe.push_back(ok ? c : L'_');
            }
            return safe;
        }
        catch (...) { return L"unknown"; }
    }

    static void appendManifestRow(const CapturedCall& item, const std::wstring& filename) noexcept
    {
        // "timestamp_utc,source_ip,caller_sid,opnum,byte_len,filename,label"
        // Label deliberately blank at capture time (spec §output format).
        HANDLE h = CreateFileW(kManifestPath,
                               FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr,
                               OPEN_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL,
                               nullptr);
        if (h == INVALID_HANDLE_VALUE) return;

        // Write a BOM only if the file is newly created (size zero).
        LARGE_INTEGER sz{};
        if (GetFileSizeEx(h, &sz) && sz.QuadPart == 0)
        {
            const wchar_t bom = 0xFEFF;
            const wchar_t header[] = L"timestamp_utc,source_ip,caller_sid,opnum,byte_len,filename,label\r\n";
            DWORD written = 0;
            WriteFile(h, &bom, sizeof(bom), &written, nullptr);
            WriteFile(h, header, sizeof(header) - sizeof(wchar_t), &written, nullptr);
        }

        wchar_t line[512];
        const int n = _snwprintf_s(line, _TRUNCATE,
            L"%s,%s,%s,%u,%u,%s,\r\n",
            item.timestampUtc.c_str(),
            item.srcAddress.empty() ? L"unknown" : item.srcAddress.c_str(),
            item.clientSid.empty()  ? L"unknown" : item.clientSid.c_str(),
            item.opnum,
            item.origLength,
            filename.c_str());
        if (n > 0)
        {
            DWORD written = 0;
            WriteFile(h, line, static_cast<DWORD>(n * sizeof(wchar_t)), &written, nullptr);
        }
        CloseHandle(h);
    }

    static void writeCaptureFile(const CapturedCall& item) noexcept
    {
        wchar_t path[MAX_PATH];
        const std::wstring safeSrc = sanitiseForFilename(
            item.srcAddress.empty() ? std::wstring(L"unknown") : item.srcAddress);

        const int n = _snwprintf_s(path, _TRUNCATE,
            L"%s\\%s_op%u_%s_%llu.bin",
            kCaptureDir,
            item.timestampUtc.c_str(),
            item.opnum,
            safeSrc.c_str(),
            static_cast<unsigned long long>(item.seq));
        if (n < 0) return;

        HANDLE h = CreateFileW(path,
                               GENERIC_WRITE,
                               FILE_SHARE_READ,
                               nullptr,
                               CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL,
                               nullptr);
        if (h == INVALID_HANDLE_VALUE) return;

        DWORD written = 0;
        if (!item.buffer.empty())
        {
            WriteFile(h,
                      item.buffer.data(),
                      static_cast<DWORD>(item.buffer.size()),
                      &written,
                      nullptr);
        }
        CloseHandle(h);

        // Basename only in the manifest row (cwd of the DC is not stable).
        const wchar_t* slash = wcsrchr(path, L'\\');
        appendManifestRow(item, slash ? slash + 1 : path);
    }

    // ---- Background writer -------------------------------------------------
    static void writerLoop() noexcept
    {
        ensureCaptureDir();
        for (;;)
        {
            std::unique_ptr<CapturedCall> item;
            {
                std::unique_lock<std::mutex> lk(gMutex);
                gCv.wait(lk, [] { return !gRunning.load() || !gQueue.empty(); });
                if (!gRunning.load() && gQueue.empty()) return;
                item = std::move(gQueue.front());
                gQueue.pop_front();
            }
            if (item)
            {
                // Any C++ fault inside the writer is contained; we drop this
                // item and keep the writer alive. No SEH here: writeCaptureFile
                // no longer touches attacker-controlled memory (that copy
                // already happened under SEH in captureRequest), and mixing
                // __try/__except with C++ destructors requires /EHa.
                try { writeCaptureFile(*item); }
                catch (...) { /* silently drop */ }
            }
        }
    }

    // ---- Public API --------------------------------------------------------
    void startCaptureThread() noexcept
    {
        if (gRunning.exchange(true)) return;
        try
        {
            gWriterThread = std::thread(&writerLoop);
        }
        catch (...)
        {
            // If we can't start the thread, disable capture entirely.
            gRunning.store(false);
        }
    }

    void stopCaptureThread() noexcept
    {
        if (!gRunning.exchange(false)) return;
        gCv.notify_all();
        try
        {
            if (gWriterThread.joinable()) gWriterThread.join();
        }
        catch (...) {}
        // Drop anything left; we're going away.
        std::lock_guard<std::mutex> lk(gMutex);
        gQueue.clear();
    }

    static bool isDrsuapi(const std::wstring& uuidString) noexcept
    {
        if (uuidString.size() != wcslen(DRSUAPI_UUID)) return false;
        return _wcsicmp(uuidString.c_str(), DRSUAPI_UUID) == 0;
    }

    bool isDrsGetNCChanges(const std::wstring& uuidString, unsigned int procNum) noexcept
    {
        return procNum == DRSUAPI_OPNUM_GETNCCHANGES && isDrsuapi(uuidString);
    }

    bool isDrsuapiInteresting(const std::wstring& uuidString, unsigned int procNum) noexcept
    {
        // Capture DsBind (0) for the DRS_EXTENSIONS_INT fingerprint research
        // and DsGetNCChanges (3) for the actual replication request payload.
        if (procNum != DRSUAPI_OPNUM_DSBIND &&
            procNum != DRSUAPI_OPNUM_GETNCCHANGES) return false;
        return isDrsuapi(uuidString);
    }

    void captureRequest(PRPC_MESSAGE pRpcMsg,
                        const std::wstring& srcAddress,
                        const std::wstring& clientSid) noexcept
    {
        // Every early-out here is deliberate: the shim must be inert unless
        // every precondition holds. Never raises; never modifies pRpcMsg.
        if (!gRunning.load(std::memory_order_relaxed)) return;
        if (!captureEnabled()) return;
        if (pRpcMsg == nullptr) return;
        if (pRpcMsg->Buffer == nullptr) return;
        if (pRpcMsg->BufferLength == 0) return;

        const uint32_t origLen = pRpcMsg->BufferLength;
        const size_t   copyLen = (origLen < kMaxCopyBytes) ? origLen : kMaxCopyBytes;

        std::unique_ptr<CapturedCall> item;
        try
        {
            item = std::make_unique<CapturedCall>();
            item->buffer.resize(copyLen);
        }
        catch (...)
        {
            return; // OOM -> drop silently
        }

        const size_t got = sehSafeCopy(item->buffer.data(), pRpcMsg->Buffer, copyLen);
        if (got != copyLen)
        {
            // Copy faulted mid-way. Discard the item; we never emit partials.
            return;
        }

        item->origLength   = origLen;
        item->opnum        = pRpcMsg->ProcNum;
        item->srcAddress   = srcAddress;
        item->clientSid    = clientSid;
        item->timestampUtc = nowUtcStamp();
        item->seq          = gSeq.fetch_add(1, std::memory_order_relaxed);

        {
            std::lock_guard<std::mutex> lk(gMutex);
            if (gQueue.size() >= kMaxQueuedItems)
            {
                // Bounded queue: on overflow drop the NEW item so the RPC
                // thread never blocks and we never grow without bound.
                return;
            }
            gQueue.push_back(std::move(item));
        }
        gCv.notify_one();
    }
}
