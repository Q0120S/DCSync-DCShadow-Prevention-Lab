// DRS Request-Inspection Module (Phase 2-4 prototype - Lab Only)
// See drsInspect.hpp header for the safety posture.
//
// Deployment model (three progressive levels, opt-in):
//
//   AUDIT   drsi_enabled                                            (default)
//           Everything is logged; nothing blocks. Safe on any DC.
//
//   DETECT  drsi_enabled + drsi_enforce_shape
//           BLOCK the "single-object CN= target from a non-partner
//           source" shape - the classic mimikatz/secretsdump network-
//           based DCSync. No known false positives when partners.txt
//           is populated correctly.
//
//   STRICT  drsi_enabled + drsi_enforce_shape + drsi_enforce_sys_loopback
//           Also BLOCK DRSUAPI opnum 3 from primary SID S-1-5-18 or
//           from loopback / link-local addresses. Catches naive
//           mimikatz-as-SYSTEM on the DC, but has legitimate false-
//           positive producers on some Windows-internal replication
//           paths. Enable ONLY after auditing decisions.log for a
//           soak period and adding any recurring benign fingerprints
//           to allowlist.txt.
//
// The legacy sentinel drsi_enforce still works and is treated as
// (enforce_shape + enforce_sys_loopback) for backward compatibility.
//
// Configuration surface (all in <DataDir>):
//   drsi_enabled                    - sentinel: module on
//   drsi_enforce_shape              - sentinel: shape BLOCK enforced
//   drsi_enforce_sys_loopback       - sentinel: sys/loopback BLOCK enforced
//   drsi_enforce                    - legacy sentinel: both of the above
//   drsi_alert_blocks               - sentinel: ALERT also blocks (careful)
//   partners.txt                    - one IPv4/IPv6 per line, comments with #
//   allowlist.txt                   - one entry per line, syntax below
//   decisions.log                   - per-decision audit trail
//   partners.log                    - partners.txt reload diagnostics
//
// allowlist.txt entry syntax (whitespace-trimmed, # for comments):
//   sid:<SID>                       - allow any call under this primary SID
//   ip:<addr>                       - allow any call from this address
//   sid+ip:<SID>@<addr>             - allow only when both match
//   ip-prefix:<prefix>              - allow when srcAddr starts with prefix
//
// <DataDir> is C:\Hardening\capture by default. Override with the REG_SZ
// HKLM\SOFTWARE\Hardening\DrsInspect\DataDir - useful for environments
// where C:\Hardening isn't appropriate (production paths, alternate volume).
//
// Design non-negotiables (unchanged from earlier iterations):
//   * Fail-OPEN on any error, unknown shape, parse fault, SEH.
//   * Bounded byte-scan; no NDR unmarshalling.
//   * Read-only: pRpcMsg and its Buffer never modified.
//   * SEH-wrapped copy of the marshalled buffer.
//   * All I/O off the RPC thread where possible; single-threaded writes
//     to log files are synchronous but bounded and cheap.

#include "pch.h"
#include <windows.h>
#include "drsInspect.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace drsinsp
{
    // ---- Data directory (lazy init, registry override) ---------------------
    static std::once_flag       gPathsInit;
    static std::wstring         gDataDir;
    static std::wstring         gEnabledPath;
    static std::wstring         gEnforceLegacyPath;
    static std::wstring         gEnforceShapePath;
    static std::wstring         gEnforceSysLoopPath;
    static std::wstring         gAlertBlocksPath;
    static std::wstring         gPartnersPath;
    static std::wstring         gAllowlistPath;
    static std::wstring         gDecisionsLogPath;
    static std::wstring         gPartnersLogPath;

    static std::wstring readRegString(HKEY root, const wchar_t* subKey, const wchar_t* name) noexcept
    {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
            return {};
        wchar_t buf[MAX_PATH];
        DWORD sz = sizeof(buf);
        DWORD type = 0;
        LSTATUS s = RegQueryValueExW(hk, name, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &sz);
        RegCloseKey(hk);
        if (s != ERROR_SUCCESS || type != REG_SZ) return {};
        // sz is bytes including the trailing NUL if the value was written correctly.
        const size_t chars = sz / sizeof(wchar_t);
        std::wstring v(buf, chars);
        while (!v.empty() && (v.back() == L'\0')) v.pop_back();
        // Trim trailing backslash for consistent joining.
        while (!v.empty() && v.back() == L'\\') v.pop_back();
        return v;
    }

    static void initPaths() noexcept
    {
        std::call_once(gPathsInit, []{
            std::wstring dir = readRegString(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Hardening\\DrsInspect", L"DataDir");
            if (dir.empty()) dir = L"C:\\Hardening\\capture";
            gDataDir             = dir;
            gEnabledPath         = dir + L"\\drsi_enabled";
            gEnforceLegacyPath   = dir + L"\\drsi_enforce";
            gEnforceShapePath    = dir + L"\\drsi_enforce_shape";
            gEnforceSysLoopPath  = dir + L"\\drsi_enforce_sys_loopback";
            gAlertBlocksPath     = dir + L"\\drsi_alert_blocks";
            gPartnersPath        = dir + L"\\partners.txt";
            gAllowlistPath       = dir + L"\\allowlist.txt";
            gDecisionsLogPath    = dir + L"\\decisions.log";
            gPartnersLogPath     = dir + L"\\partners.log";
        });
    }

    // ---- Tunables ----------------------------------------------------------
    static constexpr DWORD  kSentinelCacheMs = 1000;
    static constexpr DWORD  kPartnersCacheMs = 5000;
    static constexpr DWORD  kAllowlistCacheMs = 5000;
    static constexpr size_t kMaxScanBytes    = 8 * 1024;

    // ---- Sentinel cache ----------------------------------------------------
    struct SentinelCache { std::atomic<uint64_t> tick{0}; std::atomic<bool> present{false}; };
    static SentinelCache gEnabled;
    static SentinelCache gEnforceLegacy;
    static SentinelCache gEnforceShape;
    static SentinelCache gEnforceSysLoop;
    static SentinelCache gAlertBlocks;

    static bool checkSentinel(const std::wstring& path, SentinelCache& c) noexcept
    {
        const uint64_t now = GetTickCount64();
        if (now - c.tick.load(std::memory_order_relaxed) < kSentinelCacheMs)
            return c.present.load(std::memory_order_relaxed);
        const DWORD a = GetFileAttributesW(path.c_str());
        const bool ok = (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
        c.present.store(ok, std::memory_order_relaxed);
        c.tick.store(now, std::memory_order_relaxed);
        return ok;
    }

    bool moduleEnabled() noexcept
    {
        initPaths();
        return checkSentinel(gEnabledPath, gEnabled);
    }
    static bool enforceShape() noexcept
    {
        initPaths();
        return checkSentinel(gEnforceShapePath, gEnforceShape) ||
               checkSentinel(gEnforceLegacyPath, gEnforceLegacy);
    }
    static bool enforceSysLoopback() noexcept
    {
        initPaths();
        return checkSentinel(gEnforceSysLoopPath, gEnforceSysLoop) ||
               checkSentinel(gEnforceLegacyPath, gEnforceLegacy);
    }
    static bool alertBlocksMode() noexcept
    {
        initPaths();
        return checkSentinel(gAlertBlocksPath, gAlertBlocks);
    }

    // ---- Text-file cache utility (partners.txt / allowlist.txt) ------------
    static bool readSmallFile(const std::wstring& path, std::string& out, DWORD& err) noexcept
    {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { err = GetLastError(); return false; }
        char buf[16384];
        DWORD n = 0;
        BOOL ok = ReadFile(h, buf, sizeof(buf) - 1, &n, nullptr);
        CloseHandle(h);
        if (!ok) { err = GetLastError(); return false; }
        buf[n] = 0;
        err = 0;
        out.assign(buf, n);
        return true;
    }

    // Tokenise a file into non-empty, comment-stripped, trimmed lines.
    static std::vector<std::string> tokenise(const std::string& body) noexcept
    {
        std::vector<std::string> out;
        try
        {
            std::string line;
            for (size_t i = 0; i <= body.size(); ++i)
            {
                const char c = (i < body.size()) ? body[i] : '\n';
                if (c == '\r' || c == '\n')
                {
                    // strip trailing whitespace
                    while (!line.empty() && (line.back() == ' ' || line.back() == '\t'))
                        line.pop_back();
                    // strip leading whitespace
                    size_t j = 0;
                    while (j < line.size() && (line[j] == ' ' || line[j] == '\t')) ++j;
                    // strip comment
                    size_t hash = line.find('#', j);
                    if (hash != std::string::npos) line.resize(hash);
                    while (!line.empty() && (line.back() == ' ' || line.back() == '\t'))
                        line.pop_back();
                    if (line.size() > j) out.emplace_back(line.substr(j));
                    line.clear();
                }
                else
                {
                    line.push_back(c);
                }
            }
        }
        catch (...) { out.clear(); }
        return out;
    }

    // ---- Partners cache ----------------------------------------------------
    static std::mutex                        gPartnersMutex;
    static std::unordered_set<std::wstring>  gPartners;
    static uint64_t                          gPartnersTick = 0;

    static std::wstring wideFromNarrow(const std::string& s) noexcept
    {
        try { return std::wstring(s.begin(), s.end()); }
        catch (...) { return {}; }
    }

    static void logPartnersRefresh(size_t count, DWORD lastErr, const std::wstring& first) noexcept
    {
        HANDLE h = CreateFileW(gPartnersLogPath.c_str(), FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return;
        SYSTEMTIME st{}; GetSystemTime(&st);
        char line[512];
        const int n = _snprintf_s(line, _TRUNCATE,
            "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ partners_refresh count=%zu lastErr=%lu first=%ls\r\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            count, lastErr, first.empty() ? L"(none)" : first.c_str());
        if (n > 0) { DWORD w = 0; WriteFile(h, line, (DWORD)n, &w, nullptr); }
        CloseHandle(h);
    }

    static void refreshPartners() noexcept
    {
        std::string body;
        DWORD err = 0;
        if (!readSmallFile(gPartnersPath, body, err))
        {
            logPartnersRefresh(0, err, L"");
            return;
        }
        std::unordered_set<std::wstring> fresh;
        try
        {
            for (const auto& tok : tokenise(body))
            {
                if (!tok.empty()) fresh.insert(wideFromNarrow(tok));
            }
        }
        catch (...) { return; }

        const size_t count = fresh.size();
        const std::wstring firstEntry = count > 0 ? *fresh.begin() : std::wstring();
        {
            std::lock_guard<std::mutex> lk(gPartnersMutex);
            gPartners = std::move(fresh);
        }
        logPartnersRefresh(count, 0, firstEntry);
    }

    static bool isEstablishedPartner(const std::wstring& srcIp, size_t& listSize) noexcept
    {
        if (srcIp.empty()) { listSize = 0; return false; }
        const uint64_t now = GetTickCount64();
        if (now - gPartnersTick > kPartnersCacheMs)
        {
            refreshPartners();
            gPartnersTick = now;
        }
        std::lock_guard<std::mutex> lk(gPartnersMutex);
        listSize = gPartners.size();
        return gPartners.find(srcIp) != gPartners.end();
    }

    // ---- Allowlist cache ---------------------------------------------------
    struct AllowlistEntry
    {
        std::wstring sid;       // empty = wildcard
        std::wstring ip;        // empty = wildcard
        std::wstring ipPrefix;  // non-empty for ip-prefix: entries
    };
    static std::mutex                    gAllowMutex;
    static std::vector<AllowlistEntry>   gAllow;
    static uint64_t                      gAllowTick = 0;

    static void refreshAllowlist() noexcept
    {
        std::string body;
        DWORD err = 0;
        std::vector<AllowlistEntry> fresh;
        if (readSmallFile(gAllowlistPath, body, err))
        {
            try
            {
                for (const auto& tok : tokenise(body))
                {
                    AllowlistEntry e;
                    auto colon = tok.find(':');
                    if (colon == std::string::npos) continue;
                    const std::string kind = tok.substr(0, colon);
                    const std::string rest = tok.substr(colon + 1);
                    if (kind == "sid")
                    {
                        e.sid = wideFromNarrow(rest);
                    }
                    else if (kind == "ip")
                    {
                        e.ip = wideFromNarrow(rest);
                    }
                    else if (kind == "sid+ip")
                    {
                        auto at = rest.find('@');
                        if (at == std::string::npos) continue;
                        e.sid = wideFromNarrow(rest.substr(0, at));
                        e.ip  = wideFromNarrow(rest.substr(at + 1));
                    }
                    else if (kind == "ip-prefix")
                    {
                        e.ipPrefix = wideFromNarrow(rest);
                    }
                    else
                    {
                        continue;
                    }
                    fresh.emplace_back(std::move(e));
                }
            }
            catch (...) { fresh.clear(); }
        }
        // If file missing/unreadable, treat as empty allowlist. Not fatal.
        std::lock_guard<std::mutex> lk(gAllowMutex);
        gAllow = std::move(fresh);
    }

    static bool matchesAllowlist(const std::wstring& sid, const std::wstring& ip) noexcept
    {
        const uint64_t now = GetTickCount64();
        if (now - gAllowTick > kAllowlistCacheMs)
        {
            refreshAllowlist();
            gAllowTick = now;
        }
        std::lock_guard<std::mutex> lk(gAllowMutex);
        for (const auto& e : gAllow)
        {
            if (!e.ipPrefix.empty())
            {
                if (ip.size() >= e.ipPrefix.size() &&
                    _wcsnicmp(ip.c_str(), e.ipPrefix.c_str(), e.ipPrefix.size()) == 0)
                {
                    return true;
                }
                continue;
            }
            const bool sidOk = e.sid.empty() || _wcsicmp(sid.c_str(), e.sid.c_str()) == 0;
            const bool ipOk  = e.ip.empty()  || _wcsicmp(ip.c_str(),  e.ip.c_str())  == 0;
            if (sidOk && ipOk && !(e.sid.empty() && e.ip.empty()))
            {
                return true;
            }
        }
        return false;
    }

    // ---- SEH-safe bounded copy --------------------------------------------
    static size_t sehSafeCopy(void* dst, const void* src, size_t n) noexcept
    {
        __try { memcpy(dst, src, n); return n; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }

    // ---- Feature extraction (heuristic; documented in earlier commits) ----
    static constexpr uint32_t kExopReplObj     = 6;
    static constexpr uint32_t kExopReplSecrets = 7;

    struct Features
    {
        bool caller_is_dc_identity        = true;
        bool is_single_object_exop        = false;
        bool target_is_security_principal = false;
        bool source_is_established_partner = false;
        bool parse_ok                     = false;
        bool caller_is_local_system       = false;
        bool source_is_loopback           = false;
        bool allowlisted                  = false;
        std::wstring target_dn;
        size_t       buffer_len = 0;
        size_t       partner_count = 0;
    };

    static bool isLocalSystemPrimary(const std::wstring& sid) noexcept
    {
        return sid == L"S-1-5-18";
    }
    static bool isLoopbackAddress(const std::wstring& ip) noexcept
    {
        if (ip.empty()) return false;
        if (ip == L"::1") return true;
        if (ip.compare(0, 4, L"127.") == 0) return true;
        if (ip.compare(0, 6, L"fe80::") == 0) return true;
        if (ip.compare(0, 6, L"FE80::") == 0) return true;
        return false;
    }

    static bool findWideDn(const uint8_t* buf, size_t len,
                           std::wstring& dnOut, bool& startsWithCn) noexcept
    {
        if (len < 8) return false;
        const size_t scanEnd = (len > kMaxScanBytes ? kMaxScanBytes : len) - 6;
        for (size_t i = 0; i < scanEnd; ++i)
        {
            if (buf[i]   == 'D' && buf[i+1] == 0 &&
                buf[i+2] == 'C' && buf[i+3] == 0 &&
                buf[i+4] == '=' && buf[i+5] == 0)
            {
                size_t start = i;
                const size_t minStart = (i > 512) ? i - 512 : 0;
                while (start >= minStart + 2)
                {
                    const size_t p = start - 2;
                    const uint8_t c0 = buf[p];
                    const uint8_t c1 = buf[p+1];
                    if (c1 != 0) break;
                    if (c0 == 0 || c0 < 0x20 || c0 > 0x7E) break;
                    start = p;
                    if (start == minStart) break;
                }
                std::wstring dn;
                dn.reserve(64);
                for (size_t p = start; p + 1 < len && dn.size() < 512; p += 2)
                {
                    const uint8_t c0 = buf[p];
                    const uint8_t c1 = buf[p+1];
                    if (c1 != 0) break;
                    if (c0 == 0) break;
                    if (c0 < 0x20 || c0 > 0x7E) break;
                    dn.push_back(static_cast<wchar_t>(c0));
                }
                if (dn.size() < 3) return false;
                startsWithCn = (dn.size() >= 3 &&
                                (dn[0] == L'C' || dn[0] == L'c') &&
                                (dn[1] == L'N' || dn[1] == L'n') &&
                                dn[2] == L'=');
                dnOut = std::move(dn);
                return true;
            }
        }
        return false;
    }

    static bool findExopSingleObject(const uint8_t* buf, size_t len) noexcept
    {
        const size_t scanEnd = (len > kMaxScanBytes ? kMaxScanBytes : len);
        if (scanEnd < 4) return false;
        for (size_t i = 0; i + 4 <= scanEnd; i += 4)
        {
            uint32_t d = 0;
            memcpy(&d, buf + i, 4);
            if (d != kExopReplObj && d != kExopReplSecrets) continue;
            uint32_t prev = 0, next = 0;
            if (i >= 4)             memcpy(&prev, buf + i - 4, 4);
            if (i + 8 <= scanEnd)   memcpy(&next, buf + i + 4, 4);
            if (prev < 0x10000 && next < 0x10000) return true;
        }
        return false;
    }

    static Features extractFeatures(const uint8_t* copy, size_t len,
                                    const std::wstring& srcAddr,
                                    const std::wstring& clientSid) noexcept
    {
        Features f;
        f.buffer_len = len;
        f.caller_is_local_system = isLocalSystemPrimary(clientSid);
        f.source_is_loopback     = isLoopbackAddress(srcAddr);
        f.allowlisted            = matchesAllowlist(clientSid, srcAddr);
        try
        {
            std::wstring dn;
            bool startsWithCn = false;
            const bool dnFound = findWideDn(copy, len, dn, startsWithCn);
            const bool exopSingleObj = findExopSingleObject(copy, len);

            if (dnFound)
            {
                f.target_is_security_principal = startsWithCn;
                f.target_dn = dn;
            }
            f.is_single_object_exop = exopSingleObj && dnFound && startsWithCn;
            size_t partnerCount = 0;
            f.source_is_established_partner = isEstablishedPartner(srcAddr, partnerCount);
            f.partner_count = partnerCount;
            f.parse_ok = dnFound;
        }
        catch (...) { f.parse_ok = false; }
        return f;
    }

    // ---- Decision engine ---------------------------------------------------
    //
    // Order is deliberate:
    //   1. allowlist    -> ALLOW immediately (operator-controlled safety valve)
    //   2. shape BLOCK  -> targeted-DCSync fingerprint from non-partner
    //   3. sys+loopback -> naive mimikatz-as-SYSTEM (opt-in enforce only)
    //   4. partner ALLOW-> established partner without a suspicious shape
    //   5. fallback     -> ALERT for anything that doesn't match a rule
    //
    // Only shape and sys+loopback produce BLOCK, and each is gated by its
    // own enforce sentinel. Everything else is ALERT.
    static Verdict classify(const Features& f) noexcept
    {
        if (f.allowlisted)
        {
            return { Decision::ALLOW, "allowlist match" };
        }
        // Non-DC-identity is a hard block; SID gate should already have caught
        // this upstream, but defense in depth.
        if (!f.caller_is_dc_identity)
        {
            return { Decision::BLOCK, "replication requested under a non-DC identity" };
        }

        const bool targetedShape = f.is_single_object_exop && f.target_is_security_principal;

        // Rule 1: shape-based BLOCK. Only fires when we could parse a DN,
        // it looks like a security principal, EXOP hit, AND source is not
        // a known partner. This is the Kali / off-DC DCSync fingerprint.
        if (targetedShape && !f.source_is_established_partner)
        {
            return { Decision::BLOCK,
                     "single-object secret pull from a non-partner source (targeted DCSync)" };
        }

        // Rule 2: SYSTEM / loopback side-channel. Catches naive local mimikatz-
        // as-SYSTEM even when the parser can't extract a DN. Known false-
        // positive source on some Windows internals - enable STRICT only after
        // audit and allowlisting.
        if (f.caller_is_local_system)
        {
            return { Decision::BLOCK,
                     "DRSUAPI opnum 3 with primary SID S-1-5-18; "
                     "legitimate replication authenticates as the DC machine account" };
        }
        if (f.source_is_loopback)
        {
            return { Decision::BLOCK,
                     "DRSUAPI opnum 3 from loopback / link-local address; "
                     "legitimate replication traverses the domain network" };
        }

        // Rule 3: parse failure -> ALERT (fail-open).
        if (!f.parse_ok)
        {
            return { Decision::ALERT, "unparseable request shape (fail-open + alert)" };
        }

        // Rule 4: partner path.
        if (f.source_is_established_partner)
        {
            if (targetedShape)
            {
                return { Decision::ALERT,
                         "single-object pull from a DC-identity partner (indistinguishable; alert)" };
            }
            return { Decision::ALLOW, "established partner - normal replication" };
        }

        // Rule 5: non-partner without a clear DCSync signature.
        return { Decision::ALERT,
                 "replication from non-partner source (shape not a clear DCSync signature)" };
    }

    // ---- shouldBlock: apply enforce gating ---------------------------------
    // A verdict of BLOCK is honored only if the matching enforce sentinel is
    // present. This keeps the classifier pure and puts the operational policy
    // in one place.
    bool shouldBlock(const Verdict& v) noexcept
    {
        if (v.decision == Decision::ALLOW) return false;
        if (v.decision == Decision::ALERT)
        {
            return alertBlocksMode() && (enforceShape() || enforceSysLoopback());
        }
        // BLOCK: gate by which rule produced it. We can't recover the rule
        // identity from Verdict alone without a bigger refactor, so gate by
        // the reason text - it's a small enum in practice.
        if (v.reason == nullptr) return false;
        // sys+loopback family
        if (strstr(v.reason, "S-1-5-18") != nullptr) return enforceSysLoopback();
        if (strstr(v.reason, "loopback") != nullptr) return enforceSysLoopback();
        // shape family
        return enforceShape();
    }

    // ---- Telemetry ---------------------------------------------------------
    static const char* decisionName(Decision d) noexcept
    {
        switch (d) {
            case Decision::ALLOW: return "ALLOW";
            case Decision::ALERT: return "ALERT";
            case Decision::BLOCK: return "BLOCK";
        }
        return "?";
    }

    static void logDecision(const Verdict& v,
                            const std::wstring& srcAddr,
                            const std::wstring& clientSid,
                            const Features& f,
                            bool enforced) noexcept
    {
        HANDLE h = CreateFileW(gDecisionsLogPath.c_str(), FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return;

        SYSTEMTIME st{}; GetSystemTime(&st);
        std::wstring dnShort = f.target_dn;
        if (dnShort.size() > 200) dnShort.resize(200);

        char line[1280];
        const int n = _snprintf_s(line, _TRUNCATE,
            "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ decision=%s enforced=%d "
            "src=%ls sid=%ls buflen=%zu allowlisted=%d local_system=%d loopback=%d "
            "single_obj=%d principal=%d partner=%d partners_loaded=%zu parse_ok=%d "
            "dn=\"%ls\" reason=\"%s\"\r\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            decisionName(v.decision), enforced ? 1 : 0,
            srcAddr.empty()  ? L"unknown" : srcAddr.c_str(),
            clientSid.empty() ? L"unknown" : clientSid.c_str(),
            f.buffer_len,
            f.allowlisted ? 1 : 0,
            f.caller_is_local_system ? 1 : 0,
            f.source_is_loopback ? 1 : 0,
            f.is_single_object_exop ? 1 : 0,
            f.target_is_security_principal ? 1 : 0,
            f.source_is_established_partner ? 1 : 0,
            f.partner_count,
            f.parse_ok ? 1 : 0,
            dnShort.empty() ? L"" : dnShort.c_str(),
            v.reason ? v.reason : "");
        if (n > 0)
        {
            DWORD written = 0;
            WriteFile(h, line, static_cast<DWORD>(n), &written, nullptr);
        }
        CloseHandle(h);
    }

    // ---- Public entry ------------------------------------------------------
    Verdict inspectDrsRequest(PRPC_MESSAGE pRpcMsg,
                              const std::wstring& srcAddress,
                              const std::wstring& clientSid) noexcept
    {
        const Verdict allowByDefault{ Decision::ALLOW, "inspection unavailable (fail-open)" };
        initPaths();
        if (!moduleEnabled())           return allowByDefault;
        if (pRpcMsg == nullptr)         return allowByDefault;
        if (pRpcMsg->Buffer == nullptr) return allowByDefault;
        if (pRpcMsg->BufferLength == 0) return allowByDefault;

        const size_t copyLen =
            (pRpcMsg->BufferLength < kMaxScanBytes) ? pRpcMsg->BufferLength : kMaxScanBytes;

        std::vector<uint8_t> copy;
        try { copy.resize(copyLen); }
        catch (...) { return allowByDefault; }

        const size_t got = sehSafeCopy(copy.data(), pRpcMsg->Buffer, copyLen);
        if (got != copyLen) return allowByDefault;

        Features f;
        try { f = extractFeatures(copy.data(), copy.size(), srcAddress, clientSid); }
        catch (...) { return allowByDefault; }

        const Verdict v = classify(f);
        const bool willEnforce = shouldBlock(v);
        try { logDecision(v, srcAddress, clientSid, f, willEnforce); } catch (...) {}
        return v;
    }
}
