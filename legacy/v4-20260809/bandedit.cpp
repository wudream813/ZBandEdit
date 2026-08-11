// ============================================================================
// bandedit.cpp —— BandEdit: 窗口 Z-Band 一体化编辑工具
//
//   找窗口(scan/鼠标pick) → 查 Band(band) → 改 Band(set) 一条龙。
//
// 编译:
//   cl /std:c++17 /W4 /utf-8 bandedit.cpp /link /OUT:bandedit-x64.exe
//   g++ -std=c++17 -O2 -Wall -Wextra -municode -o bandedit-x64.exe bandedit.cpp -static
//
// 用法:
//   bandedit scan [--all]              按 Z-Band 分组绘制桌面"层级地图"
//   bandedit list [子串]               按 Z 序平铺列出顶层窗口
//   bandedit pick                      鼠标取窗：移动实时预览, F8 捕获, Esc 退出
//   bandedit band <hwnd|pick>          查询窗口 Z-Band（含标题/类名/进程）
//   bandedit set <hwnd|pick|me> <zbid> [--manual] [--dll 路径]
//                                      直接把窗口送入指定 ZBID（借 explorer 蹦床）
//   bandedit top|bottom|topmost|notopmost <hwnd|pick>   Band 内 Z 序操作
//   bandedit unload                    卸载 explorer 里的 hook 与 payload DLL
//
// hwnd/zbid 支持十进制或 0x 前缀；pick = 运行时用鼠标选取窗口。
// ⚠️ set 子命令通过注入 explorer.exe 实现，仅供自己机器研究用途。
// ============================================================================
#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>
#include <conio.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>

// ============================ 通信协议（与 payload 共享） =====================
// state: 0=空闲 1=请求 2=成功 3=调用被拒 5=hook安装失败 6=direct失败 7=诱导捕获key中 8=静默扫描中 9=卸载
// reserved[0] = 请求标志: 1=SILENT(只扫描, 禁止诱导/焦点/输入)
struct ShareBlock {
    volatile LONG      state;
    LONG               pad;
    unsigned long long hwnd;
    unsigned long long insertAfter;
    DWORD              band;
    DWORD              result;
    DWORD              error;
    DWORD              magic;        // 'ZBND'
    DWORD              ver;          // payload 协议版本(>=4 支持静默扫描)
    DWORD              mode;         // 0=trampoline 1=direct
    DWORD              flags;        // bit0:有key bit1:无#2510 bit2:本次direct执行 bit3:key来自静默扫描
    DWORD              reserved[3];
};
static const wchar_t* kShareName = L"Local\\ZBandHookShareV1";
static const wchar_t* kMutexName = L"Local\\ZBandHookPayloadReadyV1";
static const DWORD    kMagic     = 0x444E425A;

// ============================ 未公开 API 指针 =================================
using PFN_GetWindowBand = BOOL (WINAPI*)(HWND, PDWORD);
static PFN_GetWindowBand pGetWindowBand = nullptr;

// ============================ ZBID 名称 =======================================
static const wchar_t* BandName(int b) {
    switch (b) {
    case 0:  return L"ZBID_DEFAULT";
    case 1:  return L"ZBID_DESKTOP";
    case 2:  return L"ZBID_UIACCESS";
    case 3:  return L"ZBID_IMMERSIVE_IHM";
    case 4:  return L"ZBID_IMMERSIVE_NOTIFICATION";
    case 5:  return L"ZBID_IMMERSIVE_APPCHROME";
    case 6:  return L"ZBID_IMMERSIVE_MOGO";
    case 7:  return L"ZBID_IMMERSIVE_EDGY";
    case 12: return L"ZBID_IMMERSIVE_BACKGROUND";
    case 13: return L"ZBID_IMMERSIVE_SEARCH";
    case 14: return L"ZBID_GENUINE_WINDOWS";
    case 15: return L"ZBID_IMMERSIVE_RESTRICTED";
    case 16: return L"ZBID_SYSTEM_TOOLS";
    case 17: return L"ZBID_LOCK";
    case 18: return L"ZBID_ABOVELOCK_UX";
    default: return L"?";
    }
}
static const wchar_t* BandUsage(int b) {
    switch (b) {
    case 1:  return L"普通应用窗口（含 WS_EX_TOPMOST）；任务栏平时也在这";
    case 2:  return L"屏幕键盘/放大镜等 UIAccess 辅助工具";
    case 4:  return L"通知中心";
    case 5:  return L"任务视图 (Win+Tab)";
    case 6:  return L"开始菜单；开始打开时任务栏被临时提升到这里";
    case 14: return L"'激活 Windows' 水印";
    case 16: return L"任务管理器'置于顶层'、Alt+Tab 界面";
    case 17: return L"锁屏";
    case 18: return L"锁屏之上的播放控制 UX";
    default: return L"";
    }
}

// ============================ 控制台输出 ======================================
static void out(const wchar_t* s) {
    DWORD w = 0, mode = 0;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleMode(h, &mode)) WriteConsoleW(h, s, (DWORD)wcslen(s), &w, nullptr);
    else {
        int len = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
        std::string u8(len ? len - 1 : 0, '\0');
        if (len > 1) WideCharToMultiByte(CP_UTF8, 0, s, -1, u8.data(), len, nullptr, nullptr);
        WriteFile(h, u8.data(), (DWORD)u8.size(), &w, nullptr);
    }
}
static void outf(const wchar_t* fmt, ...) {
    wchar_t buf[2048];
    va_list ap; va_start(ap, fmt);
    StringCchVPrintfW(buf, 2048, fmt, ap);
    va_end(ap);
    buf[2047] = 0;
    out(buf);
}
static WORD g_oldAttr = 7;
static void colorPush(WORD attr) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (GetConsoleScreenBufferInfo(h, &info)) g_oldAttr = info.wAttributes;
    SetConsoleTextAttribute(h, attr);
}
static void colorPop() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), g_oldAttr); }
constexpr WORD kCyan   = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
constexpr WORD kYellow = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
constexpr WORD kRed    = FOREGROUND_RED | FOREGROUND_INTENSITY;
constexpr WORD kGreen  = FOREGROUND_GREEN | FOREGROUND_INTENSITY;

// ============================ 窗口信息通用函数 ================================
static DWORD BandOf(HWND hwnd) {
    DWORD b = 0xFFFFFFFF;
    if (pGetWindowBand && pGetWindowBand(hwnd, &b)) return b;
    return 0xFFFFFFFF;
}
static std::wstring TitleOf(HWND hwnd) {
    wchar_t t[256]{};
    GetWindowTextW(hwnd, t, 256);
    return t;
}
static std::wstring ClassOf(HWND hwnd) {
    wchar_t c[128]{};
    GetClassNameW(hwnd, c, 128);
    return c;
}
static std::wstring ExeOfPid(DWORD pid) {
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return L"(无权限查询)";
    wchar_t p[MAX_PATH]{}; DWORD n = MAX_PATH;
    std::wstring r = L"?";
    if (QueryFullProcessImageNameW(hp, 0, p, &n)) {
        r = p;
        size_t pos = r.find_last_of(L"\\/");
        if (pos != std::wstring::npos) r = r.substr(pos + 1);
    }
    CloseHandle(hp);
    return r;
}
static void PrintWindowInfo(HWND hwnd) {
    if (!IsWindow(hwnd)) { out(L"(窗口已不存在)\n"); return; }
    DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
    DWORD b = BandOf(hwnd);
    RECT rc{}; GetWindowRect(hwnd, &rc);
    LONG_PTR ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    bool reserved = (b != 0xFFFFFFFF && b >= 2);
    if (reserved) colorPush(kCyan); else colorPush(kGreen);
    outf(L"  hwnd = 0x%08llX   band = %d (%s)%s\n",
         (unsigned long long)(uintptr_t)hwnd, b, BandName((int)b),
         reserved ? L"  [系统保留层]" : L"");
    colorPop();
    outf(L"  标题 = \"%s\"   类名 = %s\n", TitleOf(hwnd).c_str(), ClassOf(hwnd).c_str());
    outf(L"  进程 = %d (%s)   位置 = (%ld,%ld)-(%ld,%ld)%s%s\n",
         pid, ExeOfPid(pid).c_str(), rc.left, rc.top, rc.right, rc.bottom,
         (ex & WS_EX_TOPMOST) ? L"   [TOPMOST]" : L"",
         IsWindowVisible(hwnd) ? L"" : L"   [hidden]");
}

// 前向声明
static void PumpMessages();

// ============================ 枚举: scan / list ===============================
struct WinRec {
    HWND hwnd; DWORD band; bool topmost; bool visible; DWORD pid; std::wstring title;
};
static std::vector<WinRec> g_wins;
static BOOL CALLBACK EnumTopCb(HWND hwnd, LPARAM) {
    WinRec r{};
    r.hwnd = hwnd; r.band = BandOf(hwnd);
    r.topmost = (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0;
    r.visible = IsWindowVisible(hwnd) != 0;
    GetWindowThreadProcessId(hwnd, &r.pid);
    r.title = TitleOf(hwnd);
    g_wins.push_back(std::move(r));
    return TRUE;
}
static void CmdScan(bool onlyVisible) {
    g_wins.clear();
    EnumWindows(EnumTopCb, 0);
    std::map<DWORD, std::vector<const WinRec*>> groups;
    for (const auto& w : g_wins) {
        if (onlyVisible && !w.visible) continue;
        groups[w.band].push_back(&w);
    }
    out(L"\n===== 桌面 Z-Band 层级地图（从上到下 = 物理叠放从顶到底）=====\n\n");
    for (auto it = groups.rbegin(); it != groups.rend(); ++it) {
        DWORD band = it->first;
        bool reserved = (band >= 2);
        colorPush(reserved ? kCyan : kGreen);
        outf(L"┌─ Band %2d  %-32s %s\n", band, BandName((int)band),
             reserved ? L"[系统保留层]" : L"[应用可达]");
        colorPop();
        if (BandUsage((int)band)[0]) outf(L"│   用途: %s\n", BandUsage((int)band));
        for (const WinRec* w : it->second) {
            std::wstring t = w->title;
            if (t.size() > 60) { t.resize(60); t += L"…"; }
            outf(L"│   hwnd=0x%08llX %s pid=%5u %s%s\n",
                 (unsigned long long)(uintptr_t)w->hwnd,
                 w->topmost ? L"[TOPMOST]" : L"         ",
                 w->pid, w->visible ? L"" : L"[hidden] ", t.c_str());
        }
        out(L"└────────────────────────────────────────────\n\n");
    }
    outf(L"共 %zu 个顶层窗口（仅当前桌面；锁屏/UAC 安全桌面上的窗口不可见）\n\n", g_wins.size());
}
static void CmdList(const wchar_t* filter) {
    g_wins.clear();
    EnumWindows(EnumTopCb, 0);
    int z = 0;
    out(L"\n[ z  ] hwnd        band            pid     标题\n");
    out(L"--------------------------------------------------------------\n");
    for (const auto& w : g_wins) {
        if (filter && w.title.find(filter) == std::wstring::npos) continue;
        std::wstring t = w.title;
        if (t.size() > 45) { t.resize(45); t += L"…"; }
        outf(L"[%4d] 0x%08llX %2d %-22s %5u %s%s%s\n",
             z++, (unsigned long long)(uintptr_t)w.hwnd, w.band, BandName((int)w.band),
             w.pid, w.topmost ? L"[TOP] " : L"", w.visible ? L"" : L"[hidden] ", t.c_str());
    }
    out(L"\n");
}

// ============================ 鼠标取窗 pick ====================================
// 返回被捕获的顶层窗口；multi=true 时连续捕获，Esc 结束（返回最后一个）
static HWND PickInteractive(bool multi) {
    out(L"鼠标取窗模式：移动鼠标到目标窗口上悬停预览，\n"
        L"按 [F8] 捕获并显示完整信息，按 [Esc] 结束。\n\n");
    HWND hover = nullptr, picked = nullptr;
    std::wstring lastLine;
    for (;;) {
        // Esc 优先检测（带边沿去抖）
        if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) { out(L"\n已退出取窗。\n"); return picked; }

        POINT pt{}; GetCursorPos(&pt);
        HWND h = WindowFromPoint(pt);
        HWND root = h ? GetAncestor(h, GA_ROOT) : nullptr;
        if (root != hover) {
            hover = root;
            if (hover) {
                std::wstring t = TitleOf(hover);
                if (t.size() > 30) { t.resize(30); t += L"…"; }
                wchar_t line[512];
                DWORD b = BandOf(hover);
                StringCchPrintfW(line, 512, L"\r悬停: 0x%08llX band=%2d %-22s \"%s\"%s",
                                 (unsigned long long)(uintptr_t)hover, b, BandName((int)b),
                                 t.c_str(), std::wstring(80 - 0, L' ').c_str());
                // 截断填充：用空格覆盖旧行
                std::wstring s(line);
                if (s.size() < lastLine.size()) s += std::wstring(lastLine.size() - s.size(), L' ');
                lastLine = s;
                out(s.c_str());
            }
        }
        if (GetAsyncKeyState(VK_F8) & 0x8000) {
            if (hover) {
                picked = hover;
                out(L"\n");
                colorPush(kYellow);
                outf(L"★ 捕获 hwnd=0x%08llX：\n", (unsigned long long)(uintptr_t)picked);
                colorPop();
                PrintWindowInfo(picked);
                FlashWindow(picked, TRUE);   // 让目标闪一下标题栏作为反馈
                out(L"\n");
                if (!multi) { return picked; }
            }
            Sleep(300);   // 去抖
        }
        Sleep(50);
        PumpMessages();
    }
}

// ============================ Band 内 Z 序操作 =================================
static void CmdZop(const wchar_t* op, HWND hwnd) {
    if (!IsWindow(hwnd)) { out(L"无效窗口句柄\n"); return; }
    HWND after = HWND_TOP;
    if      (!wcscmp(op, L"bottom"))    after = HWND_BOTTOM;
    else if (!wcscmp(op, L"topmost"))   after = HWND_TOPMOST;
    else if (!wcscmp(op, L"notopmost")) after = HWND_NOTOPMOST;
    if (!SetWindowPos(hwnd, after, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)) {
        outf(L"SetWindowPos 失败: err=%d\n", GetLastError());
        return;
    }
    outf(L"完成。注意：该操作只改变 Band 内的 Z 序分组，当前 band 仍是 %d (%s)\n",
         BandOf(hwnd), BandName((int)BandOf(hwnd)));
}

// ============================ 注入 / 权限 / 校验 ===============================
static void EnableDebugPrivilege() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    LUID luid{};
    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    }
    CloseHandle(tok);
}
static DWORD FindExplorerPid() {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) { pid = pe.th32ProcessID; break; }
    }
    CloseHandle(snap);
    return pid;
}
static std::wstring SelfDir() {
    wchar_t p[MAX_PATH]{};
    GetModuleFileNameW(nullptr, p, MAX_PATH);
    std::wstring s(p);
    size_t pos = s.find_last_of(L"\\/");
    return pos == std::wstring::npos ? L"." : s.substr(0, pos);
}
static WORD ProcessMachine(DWORD pid) {
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) hp = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hp) return 0;
    using PFN_IsWow64Process2 = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
    auto pFn = (PFN_IsWow64Process2)(void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    USHORT pm = 0, nm = 0;
    if (pFn && pFn(hp, &pm, &nm)) { CloseHandle(hp); return nm ? nm : pm; }
    BOOL wow = FALSE; IsWow64Process(hp, &wow); CloseHandle(hp);
#ifdef _WIN64
    return wow ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
#else
    return IMAGE_FILE_MACHINE_I386;
#endif
}
static const wchar_t* MachineName(WORD m) {
    switch (m) {
    case IMAGE_FILE_MACHINE_AMD64: return L"x64";
    case IMAGE_FILE_MACHINE_I386:  return L"x86";
    case IMAGE_FILE_MACHINE_ARM64: return L"ARM64";
    case 0:                        return L"查询失败";
    default:                       return L"其他";
    }
}
static bool ValidatePayloadPe(const std::wstring& path, std::wstring& why) {
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) { why = L"文件不存在"; return false; }
    BYTE hdr[1024]; DWORD rd = 0; LARGE_INTEGER sz{};
    GetFileSizeEx(hf, &sz);
    BOOL ok = ReadFile(hf, hdr, sizeof(hdr), &rd, nullptr);
    CloseHandle(hf);
    if (!ok || rd < 512) { why = L"读取文件头失败（下载不完整？）"; return false; }
    if (sz.QuadPart < 20000) { why = L"文件太小，疑似下载不完整/被杀软清空"; return false; }
    if (hdr[0] != 'M' || hdr[1] != 'Z') { why = L"不是有效 PE（无 MZ 头）"; return false; }
    DWORD peOff = *(DWORD*)(hdr + 0x3C);
    if (peOff + 6 > rd || hdr[peOff] != 'P' || hdr[peOff+1] != 'E' || hdr[peOff+2] || hdr[peOff+3]) {
        why = L"不是有效 PE（无 PE 签名）"; return false;
    }
    WORD machine = *(WORD*)(hdr + peOff + 4);
    if (machine != IMAGE_FILE_MACHINE_AMD64) { why = L"payload 不是 x64 架构"; return false; }
    return true;
}
// 扫描 payload 文件里的版本标识 "BANDPAYLOAD_VER=N"（v1 没有该标识 → 返回 1）
static int PayloadFileVersion(const std::wstring& path) {
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return 1;
    LARGE_INTEGER sz{}; GetFileSizeEx(hf, &sz);
    if (sz.QuadPart <= 0 || sz.QuadPart > 8 * 1024 * 1024) { CloseHandle(hf); return 1; }
    std::vector<BYTE> buf((size_t)sz.QuadPart);
    DWORD rd = 0;
    BOOL ok = ReadFile(hf, buf.data(), (DWORD)buf.size(), &rd, nullptr);
    CloseHandle(hf);
    if (!ok) return 1;
    static const char kMarker[] = "BANDPAYLOAD_VER=";
    const size_t mlen = sizeof(kMarker) - 1;
    if (rd >= mlen + 1) {
        for (size_t i = 0; i + mlen + 1 <= rd; ++i) {
            if (memcmp(buf.data() + i, kMarker, mlen) == 0) {
                int v = buf[i + mlen] - '0';
                return (v >= 1 && v <= 9) ? v : 1;
            }
        }
    }
    return 1;
}

static bool LocatePayload(const std::wstring& explicitPath, std::wstring& found,
                          std::wstring& report, int& foundVer) {
    std::vector<std::wstring> candidates;
    if (!explicitPath.empty()) {
        wchar_t full[MAX_PATH]{};
        GetFullPathNameW(explicitPath.c_str(), MAX_PATH, full, nullptr);
        candidates.push_back(full);
    } else {
        candidates.push_back(SelfDir() + L"\\bandedit-payload-x64.dll");
        candidates.push_back(SelfDir() + L"\\bandpayload-x64.dll");
        candidates.push_back(SelfDir() + L"\\bandpayload.dll");
        candidates.push_back(SelfDir() + L"\\bandedit-payload-x64 (1).dll");
        candidates.push_back(SelfDir() + L"\\bandpayload-x64 (1).dll");
    }
    std::wstring log;
    for (auto& c : candidates) {
        std::wstring why;
        if (ValidatePayloadPe(c, why)) {
            found = c;
            foundVer = PayloadFileVersion(c);
            return true;
        }
        log += L"  ✗ " + c + L"  (" + why + L")\n";
    }
    report = log;
    return false;
}
static bool PayloadModulePresent(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    bool found = false;
    for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me)) {
        if (wcsstr(me.szModule, L"bandedit-payload") || wcsstr(me.szModule, L"bandpayload")) { found = true; break; }
    }
    CloseHandle(snap);
    return found;
}
static bool InjectDll(DWORD pid, const std::wstring& dllPath) {
    HANDLE hp = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
                            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hp) { outf(L"OpenProcess(explorer) 失败: err=%d\n", GetLastError()); return false; }
    SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* buf = VirtualAllocEx(hp, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { out(L"VirtualAllocEx 失败\n"); CloseHandle(hp); return false; }
    bool ok = WriteProcessMemory(hp, buf, dllPath.c_str(), bytes, nullptr) != 0;
    if (!ok) { out(L"WriteProcessMemory 失败\n"); VirtualFreeEx(hp, buf, 0, MEM_RELEASE); CloseHandle(hp); return false; }
    auto loadW = (LPTHREAD_START_ROUTINE)(void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE ht = CreateRemoteThread(hp, nullptr, 0, loadW, buf, 0, nullptr);
    if (!ht) {
        outf(L"CreateRemoteThread 失败: err=%d (被杀软拦截注入？)\n", GetLastError());
        VirtualFreeEx(hp, buf, 0, MEM_RELEASE); CloseHandle(hp); return false;
    }
    WaitForSingleObject(ht, 15000);
    DWORD code = 0;
    GetExitCodeThread(ht, &code);
    CloseHandle(ht);
    VirtualFreeEx(hp, buf, 0, MEM_RELEASE);
    CloseHandle(hp);
    if (code) return true;
    if (PayloadModulePresent(pid)) {
        out(L"  (模块快照显示 payload 其实已加载，HMODULE 低32位误报) → 继续\n");
        return true;
    }
    out(L"\n远程 LoadLibraryW 返回 NULL。常见原因：\n"
        L"  1) 杀软/Defender 拦截了 DLL 加载（查杀软日志，加白重试）\n"
        L"  2) 浏览器下载的文件带 MotW：右键 payload DLL → 属性 → 解除锁定\n"
        L"  3) AppLocker/组策略限制：把文件移出 Downloads 到 C:\\Temp 再试\n"
        L"  4) ARM64 设备：payload 需要 ARM64 版\n\n");
    return false;
}

// ============================ 触发 / 演示窗口 ===================================
static void PressWinKey() {
    keybd_event(VK_LWIN, 0, 0, 0);
    Sleep(80);
    keybd_event(VK_LWIN, 0, KEYEVENTF_KEYUP, 0);
}
static const wchar_t* kDemoClass = L"BandEditDemoWnd";
static HWND CreateDemoWindow() {
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = DefWindowProcW;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kDemoClass;
    RegisterClassExW(&wc);
    return CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, kDemoClass,
                           L"BandEdit 测试窗口 (按任意键结束)",
                           WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           200, 200, 460, 260, nullptr, nullptr,
                           GetModuleHandleW(nullptr), nullptr);
}
static void PumpMessages() {
    MSG msg;
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

// ============================ set: 修改指定窗口的 Band ==========================
static int CmdSet(const std::wstring& targetArg, DWORD band, bool manual, bool direct,
                  bool silent, const std::wstring& dllArg, ShareBlock* sh) {
    // 1) 目标窗口（hwnd / pick / me）
    HWND target = nullptr;
    bool meMode = false;
    if (!_wcsicmp(targetArg.c_str(), L"me")) {
        meMode = true;
    } else if (!_wcsicmp(targetArg.c_str(), L"pick")) {
        target = PickInteractive(false);
        if (!target) { out(L"未选择窗口。\n"); return 1; }
    } else {
        target = (HWND)(uintptr_t)wcstoull(targetArg.c_str(), nullptr, 0);
        if (!IsWindow(target)) { out(L"无效的窗口句柄（用 bandedit list/scan 查询，或用 pick）\n"); return 1; }
    }
    DWORD pid = FindExplorerPid();
    if (!pid) { out(L"找不到 explorer.exe\n"); return 1; }
    WORD mach = ProcessMachine(pid);
    if (mach == IMAGE_FILE_MACHINE_ARM64) {
        out(L"❌ explorer 是 ARM64 进程，需要 ARM64 版 payload。\n");
        return 1;
    }

    // 2) payload 定位（已驻留则可跳过文件校验？仍需注入时必须有文件）
    HANDLE ready = OpenMutexW(SYNCHRONIZE, FALSE, kMutexName);
    if (ready) {
        out(L"payload 已驻留 explorer，直接复用。\n");
        CloseHandle(ready);
        // direct 模式需要 v4 payload；旧版驻留时提示先卸载
        if (direct && sh->ver < 4) {
            colorPush(kYellow);
            outf(L"⚠️ 驻留的是 v%d payload（--direct 需要 v4）。\n"
                 L"   请先运行 bandedit unload，再重试。\n", sh->ver ? sh->ver : 1);
            colorPop();
            return 1;
        }
    } else {
        std::wstring dllPath, report;
        int dllVer = 1;
        if (!LocatePayload(dllArg, dllPath, report, dllVer)) {
            out(L"未找到 payload DLL，尝试过的路径：\n");
            out(report.c_str());
            out(L"把 bandedit-payload-x64.dll 放到本程序同目录，或用 --dll 指定。\n");
            return 1;
        }
        if (dllVer < 4) {
            colorPush(kYellow);
            outf(L"⚠️ 选中的 payload 是 v%d（排除法结论）—— 仅支持蹦床模式\n", dllVer);
            colorPop();
        }
        if (direct && dllVer < 4) {
            colorPush(kRed);
            out(L"❌ --direct 需要 v4 payload：请下载新版 bandedit-payload-x64.dll，\n"
                L"   并删除/移走旧文件。\n");
            colorPop();
            return 1;
        }
        outf(L"payload: %s  ✓ (v%d)\n目标 explorer.exe pid=%d (%s)，注入中...\n",
             dllPath.c_str(), dllVer, pid, MachineName(mach));
        EnableDebugPrivilege();
        if (!InjectDll(pid, dllPath)) return 1;
        for (int i = 0; i < 100; ++i) {
            ready = OpenMutexW(SYNCHRONIZE, FALSE, kMutexName);
            if (ready) { CloseHandle(ready); break; }
            Sleep(100); PumpMessages();
        }
        if (!ready) { out(L"payload 已加载但未就绪（hook 失败/系统不兼容?）\n"); return 1; }
        out(L"payload 就绪，hook 已安装在 user32!SetWindowBand。\n");
    }

    if (InterlockedCompareExchange(&sh->state, 0, 0) == 5) {
        out(L"payload 报告 hook 安装失败（需要 Windows 8+）。\n");
        return 1;
    }

    // 3) me 模式此时才创建窗口（保证注入链路全绿再出现）
    if (meMode) {
        target = CreateDemoWindow();
        if (!target) { out(L"创建测试窗口失败\n"); return 1; }
        outf(L"已创建测试窗口 hwnd=0x%08llX\n", (unsigned long long)(uintptr_t)target);
    }
    if (!IsWindow(target)) { out(L"目标窗口已关闭。\n"); return 1; }

    // 4) 下发请求（先复位清除遗留 pending，再填参数）
    InterlockedExchange(&sh->state, 0);
    Sleep(60);
    sh->hwnd        = (unsigned long long)(uintptr_t)target;
    sh->insertAfter = 0;
    sh->band        = band;
    sh->result      = 0;
    sh->error       = 0;
    sh->mode        = direct ? 1UL : 0UL;
    sh->reserved[0] = silent ? 1UL : 0UL;      // SILENT: 只扫描, 禁止诱导/焦点/输入
    InterlockedExchange(&sh->state, 1);
    if (direct)
        outf(L"[direct%s] 请求: hwnd=0x%08llX -> ZBID %d (%s)\n",
             silent ? L"+silent" : L"",
             (unsigned long long)(uintptr_t)target, band, BandName((int)band));
    else
        outf(L"[trampoline] 请求: hwnd=0x%08llX -> ZBID %d (%s)（劫持 explorer 的调用）\n",
             (unsigned long long)(uintptr_t)target, band, BandName((int)band));
    Sleep(400);

    // 5) 触发策略:
    //    trampoline: 立即按 Win（劫持那次 band 调用）
    //    direct(v3): 无需按键！payload 在 explorer 内部"自诱导" IAM 调用并捕获 key
    DWORD t0 = GetTickCount();
    LONG st = 1;
    bool triggered = false;
    int  toldManual = 0;
    while (GetTickCount() - t0 < 60000) {
        PumpMessages();
        if (_kbhit()) { InterlockedExchange(&sh->state, 0); break; }
        st = InterlockedCompareExchange(&sh->state, 0, 0);
        if (st != 1 && st != 7 && st != 8) break;

        if (direct) {
            // direct: 纯等待；payload 内部先静默扫描，必要时焦点诱导。各阶段提示一次
            if (st == 8 && toldManual != 2) {
                out(L"[阶段A] 静默扫描 explorer 内存验证候选 key（零按键/零焦点变化）...\n");
                toldManual = 2;
            } else if (st == 7 && !toldManual) {
                out(L"[阶段B] 扫描未命中，payload 在 explorer 内部诱导 IAM 调用（任务栏焦点抖动）...\n");
                toldManual = 1;
            }
        } else if (!triggered) {
            if (manual) {
                if (!toldManual) {
                    out(L"\n>>> 请手动按 Win（Win10）或 Win+Tab（Win11）触发，最多等 60s ...\n");
                    toldManual = true;
                }
            } else {
                PressWinKey();
                triggered = true;
                out(L"已模拟 Win 键触发开始菜单。\n");
            }
        } else if (!manual && GetTickCount() - t0 > 9000) {
            out(L"自动触发未生效，转手动：请按 Win / Win+Tab ...\n");
            manual = true;
        }
        Sleep(30);
    }

    if (triggered && (st == 2 || st == 3 || st == 6)) { Sleep(600); PressWinKey(); }   // 还原开始菜单

    if (st == 1) {
        out(L"\n超时未等到 explorer 调用。payload 仍驻留，可手动触发后重试本命令。\n");
        InterlockedExchange(&sh->state, 0);
    } else if (st == 7 || st == 8) {
        colorPush(kYellow);
        out(L"\n超时：key 获取未完成。可:\n"
            L"  · 手动按 Win / Win+Tab / 点一下任务栏再重试（会在 explorer 里制造 IAM 调用）\n"
            L"  · 不带 --silent 重试（允许焦点诱导兜底）\n"
            L"  · 或不带 --direct 回到蹦床模式（永远可用）\n");
        colorPop();
        InterlockedExchange(&sh->state, 0);
    } else if (st == 2) {
        bool viaDirect = (sh->flags & 4) != 0;   // payload 回传真实执行路径
        colorPush(kGreen);
        outf(L"\n✅ SetWindowBand 执行成功（%s）。\n",
             viaDirect ? L"direct 直调" : L"蹦床劫持");
        colorPop();
        if (direct && !viaDirect)
            out(L"    注：请求的是 --direct，但实际按蹦床路径完成（payload 未支持/未走直调）。\n");
        if (sh->flags & 8)
            out(L"    IAM key 获取途径: 静默内存扫描（零按键/零焦点变化）。\n");
        if (sh->flags & 1)
            out(L"    IAM key 已缓存在 payload 内存中 —— 之后的 --direct 请求毫秒级完成。\n");
    } else if (st == 3) {
        colorPush(kRed);
        outf(L"\n❌ explorer 上下文调用被拒绝: err=%d\n", sh->error);
        colorPop();
    } else if (st == 6) {
        colorPush(kRed);
        if (sh->error == 1001)
            out(L"\n❌ direct 失败: user32.dll 没有 2510 号序号导出（版本过老/过新?）。\n");
        else if (sh->error == 1002)
            out(L"\n❌ direct 失败: 已捕获 key 但 EnableIAM(key,TRUE) 返回 FALSE。\n");
        else if (sh->error == 1003)
            out(L"\n❌ direct 失败: payload 在 explorer 内诱导 IAM 调用 3 轮仍未捕获 key。\n");
        else if (sh->error == 1005)
            out(L"\n❌ silent 模式: 静默扫描未在 explorer 内存中找到 key（未做任何诱导）。\n"
                L"   可去掉 --silent 允许焦点诱导兜底。\n");
        else
            outf(L"\n❌ direct 失败: EnableIAM 层报错, err=%d\n", sh->error);
        colorPop();
    }

    // 6) 验证
    if ((st == 2 || st == 3 || st == 6) && IsWindow(target)) {
        DWORD b = BandOf(target);
        if (b == band) {
            colorPush(kGreen);
            outf(L"验证: GetWindowBand = %d (%s) —— 🎉 已升入目标 Band！\n", b, BandName((int)b));
            colorPop();
            outf(L"可以用 bandedit scan 在 Band %d 分组里看到它。\n", band);
        } else {
            outf(L"验证: GetWindowBand = %d (%s) —— 与请求不一致（系统可能已修补该路径）\n",
                 b, BandName((int)b));
        }
    }

    if (meMode && (st == 2 || st == 3 || st == 6)) {
        out(L"\n测试窗口保留中，按任意键销毁并退出...\n");
        while (!_kbhit()) { PumpMessages(); Sleep(30); }
        _getch();
    }
    if (meMode && IsWindow(target)) DestroyWindow(target);
    return st == 2 ? 0 : 2;
}

// ============================ main ============================================
static HWND ResolveTarget(const std::wstring& arg) {
    if (!_wcsicmp(arg.c_str(), L"pick")) return PickInteractive(false);
    HWND h = (HWND)(uintptr_t)wcstoull(arg.c_str(), nullptr, 0);
    return h;
}

static void Usage() {
    colorPush(kYellow);
    out(L"\nBandEdit —— 窗口 Z-Band 一体化编辑器\n");
    colorPop();
    out(L"  找窗口:\n"
        L"    bandedit scan [--all]                 按 Band 分组绘制层级地图\n"
        L"    bandedit list [子串]                  平铺列出顶层窗口(含hwnd)\n"
        L"    bandedit pick                         鼠标取窗(悬停预览, F8 捕获, Esc 退出)\n"
        L"  查询:\n"
        L"    bandedit band <hwnd|pick>             查询窗口的 Z-Band\n"
        L"  修改:\n"
        L"    bandedit set <hwnd|pick|me> <zbid> [--manual] [--direct] [--silent] [--dll 路径]\n"
        L"                                          把窗口直接改到指定 ZBID (0~18)\n"
        L"        --direct    高级模式: payload 内获取 IAM key 后直调 SetWindowBand\n"
        L"                    (先静默内存扫描, 必要时焦点诱导; 之后请求毫秒级)\n"
        L"        --silent    严格静默: 仅扫描+验证, 绝不按键/改焦点(配合 --direct)\n"
        L"    bandedit top|bottom|topmost|notopmost <hwnd|pick>\n"
        L"                                          Band 内 Z 序微调\n"
        L"  维护:\n"
        L"    bandedit unload                       卸载 explorer 内的 hook/DLL\n"
        L"\n  例: bandedit set pick 16     (鼠标点一个窗口, 送进 ZBID_SYSTEM_TOOLS)\n"
        L"      bandedit set me 2        (测试窗口送入 ZBID_UIACCESS 试试被拒?)\n\n");
}

int wmain(int argc, wchar_t** argv) {
#ifndef _WIN64
    out(L"错误：必须以 64 位编译运行。\n");
    return 1;
#endif
    pGetWindowBand = (PFN_GetWindowBand)(void*)GetProcAddress(
        GetModuleHandleW(L"user32.dll"), "GetWindowBand");

    if (argc < 2) { Usage(); return 0; }
    const wchar_t* cmd = argv[1];

    // 观察类命令不需要共享内存/注入
    if (!wcscmp(cmd, L"scan")) { CmdScan(!(argc >= 3 && !wcscmp(argv[2], L"--all"))); return 0; }
    if (!wcscmp(cmd, L"list")) { CmdList(argc >= 3 ? argv[2] : nullptr); return 0; }
    if (!wcscmp(cmd, L"pick")) { PickInteractive(true); return 0; }
    if (!wcscmp(cmd, L"band")) {
        if (argc < 3) { Usage(); return 1; }
        HWND h = ResolveTarget(argv[2]);
        if (!h) { out(L"未选择窗口。\n"); return 1; }
        out(L"\n");
        PrintWindowInfo(h);
        return 0;
    }
    if (!wcscmp(cmd, L"top") || !wcscmp(cmd, L"bottom") ||
        !wcscmp(cmd, L"topmost") || !wcscmp(cmd, L"notopmost")) {
        if (argc < 3) { Usage(); return 1; }
        HWND h = ResolveTarget(argv[2]);
        if (!h) { out(L"未选择窗口。\n"); return 1; }
        CmdZop(cmd, h);
        return 0;
    }

    // set / unload 需要共享内存
    if (wcscmp(cmd, L"set") && wcscmp(cmd, L"unload")) { Usage(); return 1; }

    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                     0, sizeof(ShareBlock), kShareName);
    if (!hMap) { outf(L"CreateFileMapping 失败: err=%d\n", GetLastError()); return 1; }
    bool fresh = GetLastError() != ERROR_ALREADY_EXISTS;
    auto* sh = (ShareBlock*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ShareBlock));
    if (!sh) { out(L"MapViewOfFile 失败\n"); return 1; }
    if (fresh) ZeroMemory(sh, sizeof(*sh));
    sh->magic = kMagic;

    if (!wcscmp(cmd, L"unload")) {
        HANDLE m = OpenMutexW(SYNCHRONIZE, FALSE, kMutexName);
        if (!m) { out(L"payload 未驻留，无需卸载。\n"); return 0; }
        CloseHandle(m);
        InterlockedExchange(&sh->state, 9);
        out(L"已请求卸载：payload 将摘除 hook 并自我释放。\n");
        return 0;
    }

    // ---- set ----
    std::wstring targetArg, bandArg, dllArg;
    bool manual = false, direct = false, silent = false;
    for (int i = 2; i < argc; ++i) {
        if (!wcscmp(argv[i], L"--manual")) manual = true;
        else if (!wcscmp(argv[i], L"--direct")) direct = true;
        else if (!wcscmp(argv[i], L"--silent")) silent = true;
        else if (!wcscmp(argv[i], L"--dll") && i + 1 < argc) dllArg = argv[++i];
        else if (targetArg.empty()) targetArg = argv[i];
        else if (bandArg.empty())   bandArg = argv[i];
    }
    if (targetArg.empty() || bandArg.empty()) { Usage(); return 1; }
    DWORD band = wcstoul(bandArg.c_str(), nullptr, 0);
    if (band > 18) { out(L"zbid 应在 0~18 之间\n"); return 1; }

    out(L"\n==== BandEdit set (借 explorer 调 SetWindowBand) ====\n");
    out(L"⚠️ 将注入 explorer.exe，仅限自己机器研究用途。\n");
    if (direct) out(L"模式: direct（payload 直调：先静默内存扫描取 key，必要时焦点诱导兜底）\n\n");
    else        out(L"模式: trampoline（劫持 explorer 的调用，需触发一次）\n\n");
    int rc = CmdSet(targetArg, band, manual, direct, silent, dllArg, sh);
    UnmapViewOfFile(sh);
    CloseHandle(hMap);
    return rc;
}
