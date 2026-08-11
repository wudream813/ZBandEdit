// ============================================================================
// bandedit.cpp —— BandEdit: 窗口 Z-Band 一体化编辑工具（单文件版）
//
//   找窗口(scan/鼠标pick) → 查 Band(band) → 改 Band(set) 一条龙。
//   payload DLL 已内嵌（payload_bin.h），分发只需 bandedit-x64.exe 一个文件。
//   注入采用【手动映射】：不经 LoadLibrary —— 不落盘、不进 PEB 模块链表，
//   Toolhelp32 模块枚举不可见（映像隶属 explorer 内的 MEM_PRIVATE 匿名区）。
//
// 构建（需先编出 payload，再由 bin2c 生成头，最后编本文件）:
//   cl /LD bandpayload.cpp /Fe:bandedit-payload-x64.dll
//   cl bin2c.cpp /Fe:bin2c.exe && bin2c bandedit-payload-x64.dll payload_bin.h
//   cl /std:c++17 /W4 /utf-8 bandedit.cpp /Fe:bandedit-x64.exe
//   （MinGW 同理，见 build_bandedit.bat）
//
// 用法:
//   bandedit scan [--all]              按 Z-Band 分组绘制桌面"层级地图"
//   bandedit list [子串]               按 Z 序平铺列出顶层窗口
//   bandedit                           （裸启动）只装载 hook：注入 payload 到 explorer 后退出
//   bandedit pick                      鼠标取窗：移动实时预览, F8 捕获, Esc 退出
//   bandedit band <hwnd|pick>          查询窗口 Z-Band（含标题/类名/进程）
//   bandedit set <hwnd|pick|me> <zbid> [--trampoline] [--induce] [--dll 路径]
//                                      直接把窗口送入指定 ZBID（借 explorer 之手）
//       （默认）direct 直调：payload 静默扫描内存取 IAM key（零按键/零焦点）
//       --trampoline 回退蹦床模式：劫持 explorer 一次 band 调用（可加 --manual 手动触发）
//       --induce   扫描未命中时的兜底：允许在 explorer 内诱导一次 IAM 调用
//       --dll 路径 （调试）用外部 payload DLL 覆盖内嵌版
//   bandedit top|bottom|topmost|notopmost <hwnd|pick>   Band 内 Z 序操作
//   bandedit unload                    卸载 explorer 里的 hook 与 payload 映像
//   全局开关 --debug（任意位置）：铺崩溃黑匣子 + 打印 payload 遥测
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
#include "payload_bin.h"   // kEmbeddedPayload / kEmbeddedPayloadLen（bin2c 生成）

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
    DWORD              flags;        // bit0:有key bit1:无#2510 bit2:本次direct执行 bit3:key来自静默扫描 bit4:已回滚顺带的TOPMOST
    DWORD              reserved[6];   // [0]=请求标志(SILENT) [1]=payload相位 [2]=主循环心跳戳 [3]=最近state
    // ---- v14(v6.1) 追加：免 --debug 的法医字段（与 payload 布局逐字节一致）----
    volatile LONG      loopCount;     // 主循环圈数（与心跳戳互证活性）
    DWORD              workerTid;     // 主循环线程 TID
    DWORD              execTid;       // 常驻执行线程 TID
    DWORD              deathTid;      // VEH 冻结线程 TID（0=无；提交标志，最后写）
    DWORD              deathCode;     //  异常码
    DWORD              deathPhase;    //  相位
    DWORD              deathPadA;     //  对齐占位
    DWORD              deathPadB;
    DWORD              deathPadC;
    ULONGLONG          deathRip;      //  RIP（配 deathBase 算 RVA）
    ULONGLONG          deathRsp;
    ULONGLONG          deathAux;      //  AV 目标地址
    ULONGLONG          deathBase;     //  payload 映像基址
};
static const wchar_t* kShareName = L"Local\\ZBandHookShareV1";
static const wchar_t* kMutexName = L"Local\\ZBandHookPayloadReadyV1";
static const DWORD    kMagic     = 0x444E425A;
static const DWORD    kNeedVer   = 14;  // v6.1: 死亡笔记 / TID 探针 / 圈数活性轴
static bool           g_debug    = false;   // --debug：铺崩溃黑匣子 + 打印遥测（平时零诊断痕迹）

// ---- 与 payload 共享的黑匣子（崩溃记录）协议，结构与 bandpayload.cpp 保持一致 ----
struct CrashBox {
    DWORD     magic;      // 'XBX1'
    DWORD     caught;
    DWORD     code;
    DWORD     phase;
    DWORD     tid;
    DWORD     pad;
    ULONGLONG rip, rsp;
    ULONGLONG rax, rbx, rcx, rdx, r8;
    ULONGLONG base;
    ULONGLONG faultAddr;
    // ---- v5.3 活埋式遥测（无异常也持续更新；前缀布局与 XBX1 兼容的追加） ----
    ULONGLONG beats;      // payload 主循环心跳
    DWORD     stateSeen;  // payload 最近读到的 state
    DWORD     auxPad;
    ULONGLONG aux;        // 扫描推进地址等实况
};
static const wchar_t* kCrashBoxName = L"Local\\ZBandCrashBoxV1";
static const DWORD    kCrashMagic   = 0x31584258;   // 'XBX1'

// 黑匣子存活持有：命名映射一旦没有任何持有者就被系统销毁。注入前创建后必须全程持有，
// 直到 payload 自己 LinkCrashBox 映射了视图（v5.4 修复：原先创建后秒关 → 对象蒸发，
// payload 永远链接不上，黑匣子形同虚设；Worker 的良性异常被 VEH 冻结时都无处写记录）。
static HANDLE   g_hCrashBoxKeep = nullptr;   // 故意不关闭：随进程退出由系统回收
static CrashBox* g_pCrashBoxKeep = nullptr;

// 打开（或创建）黑匣子共享页；create=true 时不存在则新建并初始化为 magic
static HANDLE OpenCrashBox(bool create, CrashBox** outView) {
    *outView = nullptr;
    HANDLE h = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, kCrashBoxName);
    bool fresh = false;
    if (!h && create) {
        h = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                               0, sizeof(CrashBox), kCrashBoxName);
        fresh = h && GetLastError() != ERROR_ALREADY_EXISTS;
    }
    if (!h) return nullptr;
    CrashBox* cb = (CrashBox*)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(CrashBox));
    if (!cb) { CloseHandle(h); return nullptr; }
    if (fresh) { ZeroMemory(cb, sizeof(*cb)); cb->magic = kCrashMagic; }
    if (cb->magic != kCrashMagic) { UnmapViewOfFile(cb); CloseHandle(h); return nullptr; }
    *outView = cb;
    return h;   // 调用方 CloseHandle（视图自持 section 对象；读取完 UnmapViewOfFile）
}

static const wchar_t* PhaseName(DWORD p) {
    switch (p) {
    case 0:  return L"DllMain 之前（引导壳/CRT -free 入口前）";
    case 1:  return L"DllMain:ATTACH";
    case 2:  return L"DllMain:Worker 已生成";
    case 10: return L"Worker: 入口";
    case 11: return L"Worker: 共享块已连";
    case 12: return L"Worker: user32 函数已解析";
    case 13: return L"Worker: hook 已安装";
    case 14: return L"Worker: 就绪主循环";
    case 20: return L"DirectStep";
    case 21: return L"静默内存扫描中";
    case 22: return L"直调 SetWindowBand";
    case 90: return L"卸载";
    default: return L"?";
    }
}

// 执行线程打点解码（reserved[4]，v6.0）
static const wchar_t* ExecMarkName(DWORD m) {
    switch (m) {
    case 0:  return L"尚无打点";
    case 10: return L"执行线程已唤醒";
    case 11: return L"进入 DirectStep";
    case 12: return L"走缓存 key";
    case 13: return L"EnableIAM(TRUE) 前";
    case 14: return L"EnableIAM(TRUE) 后";
    case 16: return L"SetWindowBand 前";
    case 17: return L"SetWindowBand 后";
    case 19: return L"EnableIAM(FALSE) 后";
    case 20: return L"本轮处理完毕";
    case 30: return L"静默扫描前";
    case 31: return L"静默扫描后";
    default: return L"?";
    }
}

// 控制台输出前置声明（定义在下方 控制台函数 区）
static void out(const wchar_t* s);
static void outf(const wchar_t* fmt, ...);

// v6.1：探 payload 线程死活（跨进程 OpenThread + 零超时 wait）
static void PrintThreadProbe(const wchar_t* name, DWORD tid) {
    if (!tid) { outf(L"   [%s] 无记录（payload 未上报 TID —— 线程可能根本没出生）\n", name); return; }
    HANDLE h = OpenThread(THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, tid);
    if (!h) h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, tid);
    if (!h) { outf(L"   [%s] tid=%lu 探测打不开 (err=%lu)\n", name, (unsigned long)tid, (unsigned long)GetLastError()); return; }
    DWORD wr = WaitForSingleObject(h, 0);
    if (wr == WAIT_OBJECT_0) {
        DWORD code = 0; GetExitCodeThread(h, &code);
        outf(L"   [%s] tid=%lu ☠️ 已退出，退出码=0x%08lX\n", name, (unsigned long)tid, (unsigned long)code);
    } else if (wr == WAIT_TIMEOUT) {
        outf(L"   [%s] tid=%lu 还活着（阻塞/冻结/挂起中）\n", name, (unsigned long)tid);
    } else {
        outf(L"   [%s] tid=%lu 探测异常 (wait=%lu)\n", name, (unsigned long)tid, (unsigned long)wr);
    }
    CloseHandle(h);
}

// 若黑匣子里有捕获记录则打印；返回是否有记录（实现见控制台函数之后）
static bool CrashBoxReport();

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

// ============================ 黑匣子报告（实现） ===============================
static bool CrashBoxReport() {
    CrashBox* cb = nullptr;
    HANDLE h = OpenCrashBox(false, &cb);
    if (!h) return false;
    bool has = cb->caught != 0;
    if (has) {
        colorPush(kRed);
        outf(L"\n💥 黑匣子：payload 线程 %u 曾发生异常（故障线程已被冻结，explorer 未崩）。\n", cb->tid);
        colorPop();
        outf(L"   ExceptionCode = 0x%08X    阶段相位 = %u（%s）\n",
             cb->code, cb->phase, PhaseName(cb->phase));
        if (cb->base && cb->rip >= cb->base && cb->rip < cb->base + 0x100000)
            outf(L"   RIP       = 0x%llX   （在 payload 映像内, RVA=0x%llX ← 源码定位用这个; 基址=0x%llX)\n",
                 cb->rip, cb->rip - cb->base, cb->base);
        else
            outf(L"   RIP       = 0x%llX   （不在 payload 映像内[基址 0x%llX] —— 异常发自系统/其他模块代码,\n"
                 L"              常见为 Windows 内部 C++ EH 等良性事件穿过了我们的 VEH)\n",
                 cb->rip, cb->base);
        if (cb->faultAddr)
            outf(L"   访问目标  = 0x%llX   （距基址 %+lld 字节）\n",
                 cb->faultAddr, (LONGLONG)(cb->faultAddr - cb->base));
        outf(L"   RAX=0x%llX RBX=0x%llX RCX=0x%llX RDX=0x%llX R8=0x%llX RSP=0x%llX\n",
             cb->rax, cb->rbx, cb->rcx, cb->rdx, cb->r8, cb->rsp);
        out(L"   · 冻结线程还停在 explorer 里；复制本段发回即可精确定位。\n"
            L"   · bandedit crashbox clear 清记录；重启资源管理器彻底清场。\n");
    }
    // v5.3：无异常也晒实况 —— 心跳在涨=主循环活着；相位/aux 卡住=卡在那一步
    colorPush(kCyan);
    outf(L"   [遥测] 相位=%u（%s）  心跳=%llu  payload视角state=%d  aux=0x%llX\n",
         cb->phase, PhaseName(cb->phase), (unsigned long long)cb->beats,
         (int)cb->stateSeen, (unsigned long long)cb->aux);
    colorPop();
    UnmapViewOfFile(cb);
    CloseHandle(h);
    return has;
}

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
    // SWP_NOSENDCHANGING：默认 SetWindowPos 会同步向目标投递 WM_WINDOWPOSCHANGED，
    // 撞上被系统挂起的窗口（后台 UWP 等）会把调用线程永久拖住。
    if (!SetWindowPos(hwnd, after, 0, 0, 0, 0,
                      SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOSENDCHANGING)) {
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
// ============================ 手动映射注入 ======================================
// 把 payload 字节（内嵌 / --dll 文件）在 explorer 内手工展开成可执行映像：
//   1) VirtualAllocEx 整映像(RW) → 拷头+按节拷贝 → 修基址重定位 → 解析导入
//      （payload 只导入 kernel32/user32/msvcrt 等系统 DLL —— 系统模块跨进程同基址，
//        本地 GetProcAddress 拿到的地址对 explorer 直接有效）
//   2) WriteProcessMemory 写回远程，逐节 VirtualProtectEx 恢复 R-/RW/RX（全程无 RWX）
//   3) 引导壳代码(用完即释放)：先 RtlAddFunctionTable 注册 .pdata（否则 payload 内
//      硬件异常找不到展开表会直接杀掉 explorer）→ 按加载器顺序先跑 TLS 回调
//      (PROCESS_ATTACH，mingw CRT 靠它初始化) → 再调 DllEntry(ATTACH, 自裁桩)
//   4) 自裁桩(常驻 4KB)：VirtualFree(自身映像)+RtlExitUserThread，供 payload 卸载用
// 效果：无磁盘文件、PEB 模块链表与 Toolhelp32 模块枚举都不可见（MEM_PRIVATE 匿名区）。
struct MMParams {            // 引导壳代码参数块（全部 8 字节字段）
    ULONGLONG entry;                 // +0x00 DllEntry = image + AddressOfEntryPoint
    ULONGLONG image;                 // +0x08 映像基址
    ULONGLONG reserved;              // +0x10 DllMain 第3参 = 自裁桩地址
    ULONGLONG pdata;                 // +0x18 .pdata 远程地址（无则 0）
    ULONGLONG pdataCount;            // +0x20 RUNTIME_FUNCTION 条数
    ULONGLONG pRtlAddFunctionTable;  // +0x28 诊断版暂未调用（置 0 跳过）
    ULONGLONG tlsCallbacks;          // +0x30 同上
    ULONGLONG vehHandler;            // +0x38 payload 导出的 CrashHandler 远程地址
    ULONGLONG pAddVEH;               // +0x40 AddVectoredExceptionHandler（跨进程同址）
};
struct MMReport { ULONGLONG image = 0, stub = 0, loader = 0; bool hasVeh = false; }; // 注入回报（诊断）

static bool ReadWholeFile(const std::wstring& path, std::vector<BYTE>& out) {
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{}; GetFileSizeEx(hf, &sz);
    if (sz.QuadPart <= 0 || sz.QuadPart > 16 * 1024 * 1024) { CloseHandle(hf); return false; }
    out.resize((SIZE_T)sz.QuadPart);
    DWORD rd = 0;
    BOOL ok = ReadFile(hf, out.data(), (DWORD)out.size(), &rd, nullptr) && rd == out.size();
    CloseHandle(hf);
    return ok != 0;
}

static DWORD SecProt(DWORD ch) {
    bool x = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
    bool w = (ch & IMAGE_SCN_MEM_WRITE) != 0;
    bool r = (ch & IMAGE_SCN_MEM_READ) != 0;
    if (x) return w ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    if (w) return PAGE_READWRITE;
    if (r) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// 文件内 RVA → 文件偏移（节映射的逆运算；不到任何节视为落在头部区）
static SIZE_T RvaToOff(const std::vector<IMAGE_SECTION_HEADER>& secs, DWORD hdrSize,
                       DWORD rva, SIZE_T fileSize) {
    if (rva < hdrSize) return rva;
    for (const auto& s : secs) {
        DWORD span = std::max<DWORD>(s.Misc.VirtualSize, s.SizeOfRawData);
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span) {
            SIZE_T off = (SIZE_T)s.PointerToRawData + (rva - s.VirtualAddress);
            return off < fileSize ? off : SIZE_MAX;
        }
    }
    return SIZE_MAX;
}

// 在 PE 导出表里找指定符号的 RVA（解析文件缓冲；找不到返回 0）
static DWORD FindExportRva(const std::vector<BYTE>& dll,
                           const std::vector<IMAGE_SECTION_HEADER>& secs,
                           DWORD hdrSize, const char* name) {
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(dll.data() + ((IMAGE_DOS_HEADER*)dll.data())->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return 0;
    SIZE_T off = RvaToOff(secs, hdrSize, rva, dll.size());
    if (off == SIZE_MAX || off + sizeof(IMAGE_EXPORT_DIRECTORY) > dll.size()) return 0;
    auto ed = (const IMAGE_EXPORT_DIRECTORY*)(dll.data() + off);
    SIZE_T oNames = RvaToOff(secs, hdrSize, ed->AddressOfNames, dll.size());
    SIZE_T oOrds  = RvaToOff(secs, hdrSize, ed->AddressOfNameOrdinals, dll.size());
    SIZE_T oFuncs = RvaToOff(secs, hdrSize, ed->AddressOfFunctions, dll.size());
    if (oNames == SIZE_MAX || oOrds == SIZE_MAX || oFuncs == SIZE_MAX) return 0;
    for (DWORD i = 0; i < ed->NumberOfNames; ++i) {
        if (oNames + 4 * (SIZE_T)i + 4 > dll.size()) break;
        DWORD nRva = *(const DWORD*)(dll.data() + oNames + 4 * (SIZE_T)i);
        SIZE_T oName = RvaToOff(secs, hdrSize, nRva, dll.size());
        if (oName == SIZE_MAX || oName >= dll.size()) continue;
        const char* s = (const char*)(dll.data() + oName);
        if (strcmp(s, name) == 0) {
            WORD oi = *(const WORD*)(dll.data() + oOrds + 2 * (SIZE_T)i);
            if (oFuncs + 4 * (SIZE_T)oi + 4 > dll.size()) return 0;
            return *(const DWORD*)(dll.data() + oFuncs + 4 * (SIZE_T)oi);
        }
    }
    return 0;
}

static bool ManualMapImage(HANDLE hp, const std::vector<BYTE>& dll, std::wstring& err, MMReport* rep) {
    // ---- 0) PE 结构校验 --------------------------------------------------------
    if (dll.size() < 0x400) { err = L"payload 太小"; return false; }
    auto dos = (const IMAGE_DOS_HEADER*)dll.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { err = L"不是 PE（无 MZ）"; return false; }
    if ((SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > dll.size()) { err = L"PE 头越界"; return false; }
    auto nt = (const IMAGE_NT_HEADERS64*)(dll.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { err = L"无 PE 签名"; return false; }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) { err = L"不是 x64 PE"; return false; }
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) { err = L"不是 DLL"; return false; }
    const DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    const DWORD hdrSize   = std::min<DWORD>(nt->OptionalHeader.SizeOfHeaders, (DWORD)dll.size());
    const WORD  nsec      = nt->FileHeader.NumberOfSections;
    auto secsInFile = IMAGE_FIRST_SECTION(nt);
    if ((const BYTE*)(secsInFile + nsec) > dll.data() + dll.size()) { err = L"节表越界"; return false; }
    if (imageSize < 0x2000 || imageSize > 64u * 1024 * 1024) { err = L"SizeOfImage 异常"; return false; }

    // ---- 1) 远程分配整映像（先 RW，后面逐节收紧；全程不出现 RWX）-------------------
    BYTE* base = (BYTE*)VirtualAllocEx(hp, nullptr, imageSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) { err = L"VirtualAllocEx 失败 err=" + std::to_wstring(GetLastError()); return false; }

    std::vector<IMAGE_SECTION_HEADER> secs(secsInFile, secsInFile + nsec);   // 快照节表

    bool ok = false;
    do {
        // ---- 2) 本地展开映像（头 + 各节 raw→virtual）----
        std::vector<BYTE> img(imageSize, 0);
        memcpy(img.data(), dll.data(), hdrSize);
        for (WORD i = 0; i < nsec; ++i) {
            const IMAGE_SECTION_HEADER& s = secs[i];
            if (!s.SizeOfRawData) continue;
            SIZE_T srcAvail = dll.size() > s.PointerToRawData ? dll.size() - s.PointerToRawData : 0;
            SIZE_T dstAvail = imageSize  > s.VirtualAddress   ? imageSize  - s.VirtualAddress   : 0;
            SIZE_T n = std::min<SIZE_T>(s.SizeOfRawData, std::min(srcAvail, dstAvail));
            if (n) memcpy(img.data() + s.VirtualAddress, dll.data() + s.PointerToRawData, n);
        }

        // ---- 3) 基址重定位（IMAGE_REL_BASED_DIR64）----
        const LONGLONG delta = (LONGLONG)((ULONG_PTR)base - (ULONG_PTR)nt->OptionalHeader.ImageBase);
        if (delta) {
            DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            DWORD sz  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            // 内嵌 payload 已三重验证完全位置无关（0 绝对引用 → 无 .reloc），任意基址可跑；
            // 有 .reloc 才需要修（--dll 外部 CRT 版 payload 会带上）
            if (rva && sz) {
                DWORD done = 0; bool bad = false;
                while (done + sizeof(IMAGE_BASE_RELOCATION) <= sz) {
                    auto blk = (const IMAGE_BASE_RELOCATION*)(img.data() + rva + done);
                    if (blk->SizeOfBlock < 8 || done + blk->SizeOfBlock > sz) { bad = true; break; }
                    int cnt = (int)(blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                    auto ent = (const WORD*)((const BYTE*)blk + sizeof(IMAGE_BASE_RELOCATION));
                    for (int k = 0; k < cnt; ++k) {
                        WORD type = (WORD)(ent[k] >> 12), off = (WORD)(ent[k] & 0xFFF);
                        if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
                        if (type != IMAGE_REL_BASED_DIR64) { bad = true; break; }
                        SIZE_T at = (SIZE_T)blk->VirtualAddress + off;
                        if (at + 8 > imageSize) { bad = true; break; }
                        *(LONGLONG*)(img.data() + at) += delta;
                    }
                    if (bad) break;
                    done += blk->SizeOfBlock;
                }
                if (bad) { err = L"重定位表解析失败"; break; }
            }
        }

        // ---- 4) 导入解析 ----
        {
            DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            if (rva) {
                auto desc = (IMAGE_IMPORT_DESCRIPTOR*)(img.data() + rva);
                bool badf = false;
                for (; desc->Name; ++desc) {
                    if ((BYTE*)(desc + 1) > img.data() + imageSize) { badf = true; break; }
                    const char* name = (const char*)(img.data() + desc->Name);
                    std::wstring wname(name, name + strlen(name));
                    HMODULE hLoc = GetModuleHandleA(name);
                    if (!hLoc) hLoc = LoadLibraryA(name);   // 系统DLL: 本地基址 == 远程基址
                    if (!hLoc) { err = L"无法解析导入 DLL: " + wname; badf = true; break; }
                    DWORD tIn = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
                    auto tin  = (IMAGE_THUNK_DATA64*)(img.data() + tIn);
                    auto tout = (IMAGE_THUNK_DATA64*)(img.data() + desc->FirstThunk);
                    for (; tin->u1.AddressOfData; ++tin, ++tout) {
                        FARPROC fp = nullptr;
                        if (tin->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                            fp = GetProcAddress(hLoc, MAKEINTRESOURCEA(IMAGE_ORDINAL64(tin->u1.Ordinal)));
                        } else {
                            auto ibn = (const IMAGE_IMPORT_BY_NAME*)(img.data() + tin->u1.AddressOfData);
                            if ((const BYTE*)(ibn + 1) > img.data() + imageSize) break;
                            fp = GetProcAddress(hLoc, ibn->Name);
                        }
                        if (!fp) { err = L"导入函数解析失败: " + wname; badf = true; break; }
                        tout->u1.Function = (ULONGLONG)(uintptr_t)fp;
                    }
                    if (badf) break;
                }
                if (badf) break;
            }
        }

        // ---- 5) TLS 回调数组修正（从文件读优先基址 VA 计算，幂等于 .reloc 的效果）----
        ULONGLONG tlsCbs = 0;
        {
            DWORD tlsRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            if (tlsRva) {
                SIZE_T toff = RvaToOff(secs, hdrSize, tlsRva, dll.size());
                if (toff != SIZE_MAX && toff + sizeof(IMAGE_TLS_DIRECTORY64) <= dll.size()) {
                    auto ftd = (const IMAGE_TLS_DIRECTORY64*)(dll.data() + toff);
                    if (ftd->AddressOfCallBacks) {
                        SIZE_T cbRva = (SIZE_T)(ftd->AddressOfCallBacks - nt->OptionalHeader.ImageBase);
                        tlsCbs = (ULONGLONG)(uintptr_t)(base + cbRva);
                        // 目录里的指针字段强制写成远程 VA（与 .reloc 结果一致，防御未覆盖情形）
                        if (tlsRva + sizeof(IMAGE_TLS_DIRECTORY64) <= imageSize)
                            ((IMAGE_TLS_DIRECTORY64*)(img.data() + tlsRva))->AddressOfCallBacks = tlsCbs;
                        // 逐项把回调指针写为远程地址
                        SIZE_T coff = RvaToOff(secs, hdrSize, (DWORD)cbRva, dll.size());
                        if (coff != SIZE_MAX) {
                            for (int i = 0; i < 64; ++i) {
                                if (coff + 8 * (SIZE_T)i + 8 > dll.size()) break;
                                ULONGLONG va = *(const ULONGLONG*)(dll.data() + coff + 8 * (SIZE_T)i);
                                if (!va) break;
                                if (cbRva + 8 * (SIZE_T)i + 8 > imageSize) break;
                                *(ULONGLONG*)(img.data() + cbRva + 8 * (SIZE_T)i) =
                                    (ULONGLONG)(uintptr_t)base + (va - nt->OptionalHeader.ImageBase);
                            }
                        }
                    }
                }
            }
        }

        // ---- 6) 写回远程 + 逐节恢复保护 ----
        if (!WriteProcessMemory(hp, base, img.data(), imageSize, nullptr)) {
            err = L"WriteProcessMemory(映像) 失败 err=" + std::to_wstring(GetLastError()); break;
        }
        {
            DWORD old = 0;
            VirtualProtectEx(hp, base, ((SIZE_T)hdrSize + 0xFFF) & ~(SIZE_T)0xFFF, PAGE_READONLY, &old);
            for (WORD i = 0; i < nsec; ++i) {
                SIZE_T szr = std::max<SIZE_T>(secs[i].Misc.VirtualSize, secs[i].SizeOfRawData);
                szr = (szr + 0xFFF) & ~(SIZE_T)0xFFF;
                if (secs[i].VirtualAddress >= imageSize) continue;
                if (secs[i].VirtualAddress + szr > imageSize) szr = imageSize - secs[i].VirtualAddress;
                if (!szr) continue;
                DWORD o2 = 0;
                VirtualProtectEx(hp, base + secs[i].VirtualAddress, szr,
                                 SecProt(secs[i].Characteristics), &o2);
            }
        }

        // ---- 7) 常驻自裁桩（独立 4KB RX 页；payload 收到 state=9 时跳入，不返回）----
        BYTE stub[96]; SIZE_T si = 0;
        auto emitN = [&](const BYTE* p, SIZE_T n) { memcpy(stub + si, p, n); si += n; };
        auto emitP = [&](const void* v) { memcpy(stub + si, &v, 8); si += 8; };
        {
            void* vf = (void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualFree");
            void* et = (void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlExitUserThread");
            const BYTE b1[] = { 0x48,0x83,0xEC,0x28 };                 // sub rsp,0x28
            const BYTE b2[] = { 0x48,0xB9 };                           // mov rcx, imageBase
            const BYTE b3[] = { 0x31,0xD2 };                           // xor edx,edx
            const BYTE b4[] = { 0x41,0xB8,0x00,0x80,0x00,0x00 };       // mov r8d, MEM_RELEASE
            const BYTE b5[] = { 0x48,0xB8 };                           // mov rax, VirtualFree
            const BYTE b6[] = { 0xFF,0xD0 };                           // call rax
            const BYTE b7[] = { 0x48,0x83,0xC4,0x28 };                 // add rsp,0x28
            const BYTE b8[] = { 0x31,0xC9 };                           // xor ecx,ecx
            const BYTE b9[] = { 0x48,0xB8 };                           // mov rax, RtlExitUserThread
            const BYTE ba[] = { 0xFF,0xE0 };                           // jmp rax
            emitN(b1,4);  emitN(b2,2);  emitP(base);
            emitN(b3,2);  emitN(b4,6);
            emitN(b5,2);  emitP(vf);   emitN(b6,2);
            emitN(b7,4);  emitN(b8,2);
            emitN(b9,2);  emitP(et);   emitN(ba,2);
        }
        BYTE* stubPage = (BYTE*)VirtualAllocEx(hp, nullptr, 0x1000,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!stubPage) { err = L"自裁桩页分配失败"; break; }
        if (!WriteProcessMemory(hp, stubPage, stub, si, nullptr)) {
            err = L"写自裁桩失败"; VirtualFreeEx(hp, stubPage, 0, MEM_RELEASE); break;
        }
        {
            DWORD old = 0;
            VirtualProtectEx(hp, stubPage, 0x1000, PAGE_EXECUTE_READ, &old);
            FlushInstructionCache(hp, stubPage, 0x1000);
        }

        // ---- 8) 引导壳（诊断最小版：VEH → DllEntry；参数指针烘焙 imm64，零寄存器假设）----
        MMParams pm{};
        pm.entry    = (ULONGLONG)(uintptr_t)(base + nt->OptionalHeader.AddressOfEntryPoint);
        pm.image    = (ULONGLONG)(uintptr_t)base;
        pm.reserved = (ULONGLONG)(uintptr_t)stubPage;
        // v5.3：不在引导壳里远程 AddVectoredExceptionHandler —— 那样拿到的句柄留在客户端无法摘除，
        // payload 自裁后 handler 指针悬空，explorer 下次任何异常都会踩雷。现在 VEH 由 payload 在
        // InstallCrashBox 里自装自卸；保留 CrashHandler 导出仅作 DllMain 前黑匣子链接的备选入口。
        // vehHandler=0 → 引导壳 jz 分支自动跳过远程安装。
        (void)FindExportRva(dll, secs, hdrSize, "CrashHandler");
        pm.vehHandler = 0;
        pm.pAddVEH    = 0;
        // 诊断期：跳过 RtlAddFunctionTable / TLS 回调链路（CRT-free payload 无 TLS；
        // .pdata 注册暂时不紧要 —— VEH 先装，任何崩溃都会先进黑匣子）
        pm.pdata = 0; pm.pdataCount = 0;
        pm.pRtlAddFunctionTable = 0;
        pm.tlsCallbacks = 0;

        BYTE* loaderPage = (BYTE*)VirtualAllocEx(hp, nullptr, 0x1000,
                                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!loaderPage) { err = L"引导页分配失败"; break; }
        ULONGLONG pmAddr = (ULONGLONG)(uintptr_t)(loaderPage + 128);   // 参数块在引导页 +128
        BYTE sc[160]; SIZE_T sl = 0;
        auto eN = [&](const BYTE* p, SIZE_T n) { memcpy(sc + sl, p, n); sl += n; };
        {
            const BYTE c1[] = { 0x53 };                           // push rbx
            const BYTE c2[] = { 0x41,0x54 };                      // push r12
            const BYTE c3[] = { 0x41,0x55 };                      // push r13
            const BYTE c4[] = { 0x48,0xBB };                      // mov rbx, imm64(pmAddr) ← 烘焙
            const BYTE c5[] = { 0x48,0x83,0xEC,0x20 };            // sub rsp,0x20
            const BYTE c6[] = { 0x48,0x8B,0x53,0x38 };            // mov rdx,[rbx+0x38]  CrashHandler
            const BYTE c7[] = { 0x48,0x85,0xD2 };                 // test rdx,rdx
            const BYTE c8[] = { 0x74,0x0B };                      // jz +0x0B（无导出则跳过 VEH 安装）
            const BYTE c9[] = { 0xB9,0x01,0x00,0x00,0x00 };       // mov ecx,1           First=1
            const BYTE cA[] = { 0x48,0x8B,0x43,0x40 };            // mov rax,[rbx+0x40]  pAddVEH
            const BYTE cB[] = { 0xFF,0xD0 };                      // call rax
            const BYTE cC[] = { 0x48,0x8B,0x4B,0x08 };            // mov rcx,[rbx+8]     hinst=image
            const BYTE cD[] = { 0xBA,0x01,0x00,0x00,0x00 };       // mov edx,1           ATTACH
            const BYTE cE[] = { 0x4C,0x8B,0x43,0x10 };            // mov r8,[rbx+0x10]   reserved=自裁桩
            const BYTE cF[] = { 0x48,0x8B,0x03 };                 // mov rax,[rbx]       entry
            const BYTE cG[] = { 0xFF,0xD0 };                      // call rax            DllEntry(...)
            const BYTE cH[] = { 0x48,0x83,0xC4,0x20 };            // add rsp,0x20
            const BYTE cI[] = { 0x41,0x5D, 0x41,0x5C, 0x5B };     // pop r13/r12/rbx
            const BYTE cJ[] = { 0x31,0xC0 };                      // xor eax,eax
            const BYTE cK[] = { 0xC3 };                           // ret → RtlUserThreadStart
            eN(c1,1); eN(c2,2); eN(c3,2);
            eN(c4,2); memcpy(sc + sl, &pmAddr, 8); sl += 8;
            eN(c5,4);
            eN(c6,4); eN(c7,3); eN(c8,2); eN(c9,5); eN(cA,4); eN(cB,2);
            eN(cC,4); eN(cD,5); eN(cE,4); eN(cF,3); eN(cG,2);
            eN(cH,4); eN(cI,5); eN(cJ,2); eN(cK,1);
        }
        BYTE page[0x1000] = {};
        memcpy(page, sc, sl);
        memcpy(page + 128, &pm, sizeof(pm));
        if (!WriteProcessMemory(hp, loaderPage, page, sizeof(page), nullptr)) {
            err = L"写引导页失败"; VirtualFreeEx(hp, loaderPage, 0, MEM_RELEASE); break;
        }
        {
            DWORD old = 0;
            VirtualProtectEx(hp, loaderPage, 0x1000, PAGE_EXECUTE_READ, &old);
            FlushInstructionCache(hp, loaderPage, 0x1000);
        }

        HANDLE ht = CreateRemoteThread(hp, nullptr, 0,
                                       (LPTHREAD_START_ROUTINE)(void*)loaderPage,
                                       loaderPage + 128, 0, nullptr);
        if (!ht) {
            err = L"CreateRemoteThread 失败 err=" + std::to_wstring(GetLastError());
            VirtualFreeEx(hp, loaderPage, 0, MEM_RELEASE); break;
        }
        DWORD wr = WaitForSingleObject(ht, 10000);
        CloseHandle(ht);
        if (wr == WAIT_OBJECT_0)
            VirtualFreeEx(hp, loaderPage, 0, MEM_RELEASE);   // 引导页用完即焚
        // （超时则保守保留该页防 UAF —— 之后的 ready 握手仍会报告 payload 是否起来）
        if (rep) { rep->image = (ULONGLONG)(uintptr_t)base;
                   rep->stub  = (ULONGLONG)(uintptr_t)stubPage;
                   rep->loader= (ULONGLONG)(uintptr_t)loaderPage;
                   rep->hasVeh = true; }   // v5.3: VEH 由 payload 自装自卸，必定在线
        ok = true;
    } while (false);

    if (!ok) VirtualFreeEx(hp, base, 0, MEM_RELEASE);
    return ok;
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

// ================== 装载/复用 payload（手动映射注入 + 就绪握手） ==================
// set / 裸启动共用。成功返回 true 时 payload 已在 explorer 内驻留、hook 在线。
static bool EnsurePayloadResident(const std::wstring& dllArg, ShareBlock* sh) {
    DWORD pid = FindExplorerPid();
    if (!pid) { out(L"找不到 explorer.exe\n"); return false; }
    WORD mach = ProcessMachine(pid);
    if (mach == IMAGE_FILE_MACHINE_ARM64) {
        out(L"❌ explorer 是 ARM64 进程，需要 ARM64 版 payload。\n");
        return false;
    }
    // 黑匣子只在 --debug 模式下铺设（平时零诊断痕迹）
    if (g_debug && !g_hCrashBoxKeep) g_hCrashBoxKeep = OpenCrashBox(true, &g_pCrashBoxKeep);

    HANDLE ready = OpenMutexW(SYNCHRONIZE, FALSE, kMutexName);
    if (ready) {
        out(L"payload 已驻留 explorer，直接复用。\n");
        CloseHandle(ready);
        if (sh->ver < kNeedVer) {   // 旧驻留与新客户端的卸载/映射协议不兼容
            colorPush(kYellow);
            outf(L"⚠️ 驻留的是 v%d payload（本客户端需要 v%d，卸载/映射协议已变）。\n"
                 L"   请先 bandedit unload 再重试；若 unload 后仍驻留，重启资源管理器即可清掉。\n",
                 sh->ver ? sh->ver : 1, kNeedVer);
            colorPop();
            return false;
        }
    } else {
        std::vector<BYTE> dllBytes;
        if (dllArg.empty()) {
            dllBytes.assign(kEmbeddedPayload, kEmbeddedPayload + kEmbeddedPayloadLen);
            out(L"client v6.2 · payload 内嵌 v6.1（手动映射：不落盘、不进模块链表）\n");
        } else {
            if (!ReadWholeFile(dllArg, dllBytes)) {
                outf(L"❌ 无法读取 --dll 指定的文件: %s\n", dllArg.c_str());
                return false;
            }
            outf(L"payload: 外部文件 %s（调试模式, 同样走手动映射）\n", dllArg.c_str());
        }
        outf(L"目标 explorer.exe pid=%d (%s)，手动映射注入中...\n", pid, MachineName(mach));
        EnableDebugPrivilege();
        HANDLE hp = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                                FALSE, pid);
        if (!hp) { outf(L"OpenProcess(explorer) 失败: err=%d\n", GetLastError()); return false; }
        std::wstring why;
        MMReport rep;
        bool mapOk = ManualMapImage(hp, dllBytes, why, &rep);
        CloseHandle(hp);
        if (!mapOk) {
            colorPush(kRed);
            outf(L"❌ 手动映射注入失败: %s\n", why.c_str());
            colorPop();
            out(L"   常见原因：杀软/EDR 拦截了跨进程写内存(VirtualAllocEx+WriteProcessMemory)\n"
                L"   或远程线程(CreateRemoteThread) —— 查杀软日志加白后重试。\n");
            if (g_debug) CrashBoxReport();
            return false;
        }
        if (g_debug)
            outf(L"已映射：映像=0x%llX  引导页=0x%llX  自裁桩=0x%llX （黑匣子/VEH 在线）\n",
                 rep.image, rep.loader, rep.stub);
        for (int i = 0; i < 100; ++i) {
            ready = OpenMutexW(SYNCHRONIZE, FALSE, kMutexName);
            if (ready) { CloseHandle(ready); break; }
            Sleep(100); PumpMessages();
        }
        if (!ready) {
            out(L"payload 映像已展开但未就绪（hook 失败?）\n");
            if (g_debug) CrashBoxReport();
            return false;
        }
        out(L"payload 就绪：user32!SetWindowBand 已 hook（匿名内存区，模块枚举不可见）。\n");
    }

    if (InterlockedCompareExchange(&sh->state, 0, 0) == 5) {
        out(L"payload 报告 hook 安装失败（需要 Windows 8+）。\n");
        return false;
    }
    return true;
}

// ============================ set: 修改指定窗口的 Band ==========================
static int CmdSet(const std::wstring& targetArg, DWORD band, bool manual, bool direct,
                  bool induce, const std::wstring& dllArg, ShareBlock* sh) {
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

    // 2) payload 装载/复用
    if (!EnsurePayloadResident(dllArg, sh)) return 1;

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
    // direct 默认 SILENT（只静默扫描, 禁止诱导/按键/改焦点）；--induce 时放开兜底
    sh->reserved[0] = (direct && !induce) ? 1UL : 0UL;
    InterlockedExchange(&sh->state, 1);
    if (direct)
        outf(L"[direct%s] 请求: hwnd=0x%08llX -> ZBID %d (%s)\n",
             induce ? L"+induce" : L"",
             (unsigned long long)(uintptr_t)target, band, BandName((int)band));
    else
        outf(L"[trampoline] 请求: hwnd=0x%08llX -> ZBID %d (%s)（劫持 explorer 的调用）\n",
             (unsigned long long)(uintptr_t)target, band, BandName((int)band));
    Sleep(400);

    // 5) 触发策略:
    //    trampoline: 立即按 Win（劫持那次 band 调用）
    //    direct(v3): 无需按键！payload 在 explorer 内部"自诱导" IAM 调用并捕获 key
    // v6.2：取窗的 F8/Esc 经 GetAsyncKeyState 轮询，不消费控制台输入缓冲；
    //       残留按键会被下方等待循环的 _kbhit() 取消判定瞬间捕获 → "假超时"
    //       （payload 实际早已完工）。进等待循环前排干输入缓冲。
    FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE));
    while (_kbhit()) _getch();
    DWORD t0 = GetTickCount();
    LONG st = 1;
    bool triggered = false;
    bool toldStageA = false, toldStageB = false, toldManual = false;
    bool cancelled = false;
    DWORD tkLast = sh->reserved[2]; int tkMoves = 0;   // payload 心跳戳采样（共享块遥测）
    LONG  lcLast = sh->loopCount;     int lcMoves = 0; // v6.1: 主循环圈数采样（第二活性轴）
    while (GetTickCount() - t0 < 60000) {
        PumpMessages();
        if (_kbhit()) { cancelled = true; InterlockedExchange(&sh->state, 0); break; }
        st = InterlockedCompareExchange(&sh->state, 0, 0);
        DWORD tk = sh->reserved[2];
        if (tk != tkLast) { tkLast = tk; ++tkMoves; }
        LONG lc = sh->loopCount;
        if (lc != lcLast) { lcLast = lc; ++lcMoves; }
        if (st != 1 && st != 7 && st != 8) break;

        if (direct) {
            // direct: 纯等待；payload 内部先静默扫描，(仅--induce)诱导兜底。各阶段提示一次
            if (st == 8 && !toldStageA) {
                out(L"[阶段A] 静默扫描 explorer 内存验证候选 key（零按键/零焦点变化）...\n");
                toldStageA = true;
            } else if (st == 7 && !toldStageB) {
                out(L"[阶段B] 扫描未命中，payload 在 explorer 内部诱导 IAM 调用（任务栏焦点抖动）...\n");
                toldStageB = true;
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

    if (st == 1 && cancelled) {
        out(L"\n⛔ 已按键取消本次等待。\n"
            L"   注意：取消只停客户端的等待，payload 侧可能早已执行完毕 ——\n"
            L"   建议用 bandedit-x64 band <hwnd> 或 pick 复查目标窗口的实际 Band！\n");
    } else if (st == 1) {
        DWORD waitedMs = GetTickCount() - t0;
        outf(L"\n超时未等到 explorer 调用（实际等了 %.1f 秒）。payload 仍驻留。\n", waitedMs / 1000.0);
        DWORD hbStamp = sh->reserved[2];
        DWORD nowTk   = GetTickCount();
        outf(L"   [共享块遥测] 主循环: 相位=%u 最近state=%d 心跳变化=%d 圈数变化=%d 心跳停滞=%.1f秒\n",
             sh->reserved[1], (int)sh->reserved[3], tkMoves, lcMoves,
             hbStamp ? (nowTk - hbStamp) / 1000.0 : -1.0);
        outf(L"   [执行线程打点] 卡住点=%u（%s） 打点时刻=0x%08X\n",
             sh->reserved[4], ExecMarkName(sh->reserved[4]), sh->reserved[5]);
        PrintThreadProbe(L"主循环线程", sh->workerTid);
        PrintThreadProbe(L"执行线程  ", sh->execTid);
        if (sh->deathTid) {
            outf(L"   [死亡笔记] VEH 冻结线程 tid=%lu 异常码=0x%08lX 相位=%u RIP=0x%llX (RVA=0x%llX) RSP=0x%llX 目标=0x%llX\n",
                 (unsigned long)sh->deathTid, (unsigned long)sh->deathCode, sh->deathPhase,
                 (unsigned long long)sh->deathRip,
                 (unsigned long long)(sh->deathRip - sh->deathBase),
                 (unsigned long long)sh->deathRsp, (unsigned long long)sh->deathAux);
            if (sh->deathTid == sh->workerTid)
                out(L"      ↳ 被冻结的正是主循环线程本体！把 RIP/RVA 发回来对照 payload 源码定位。\n");
            else if (sh->deathTid == sh->execTid)
                out(L"      ↳ 被冻结的是常驻执行线程！主循环派单无人接——把整段发回来分析。\n");
            else
                out(L"      ↳ 被冻结的是 explorer 的其他线程——它可能握着锁，把我们间接卡死。\n");
        }
        out(L"   ↳ 判读表：心跳/圈数=0 且线程活着而无死亡笔记 → 外部挂起/无名锁；\n"
            L"     线程已退出 → 有东西在杀非模块线程（AV/EDR 特征扫描）；\n"
            L"     打点=13 → EnableIAM 挂win32k；打点=16 → SetWindowBand 挂win32k。\n");
        InterlockedExchange(&sh->state, 0);
    } else if (st == 7 || st == 8) {
        colorPush(kYellow);
        out(L"\n超时：key 获取未完成。可：\n"
            L"  · 重试一次（内存扫描通常 1~2 秒内完成；成功后 key 缓存、之后毫秒级）\n"
            L"  · 加 --induce：允许 payload 在 explorer 内诱导一次 IAM 调用（焦点轻微抖动）\n"
            L"  · 或不带 --direct 回到蹦床模式（永远可用，但需要触发一次）\n");
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
            out(L"    IAM key 获取途径: 静默内存扫描（全程零按键/零焦点变化）。\n");
        if (sh->flags & 1)
            out(L"    IAM key 已缓存在 payload 内存中 —— 后续的 set 请求毫秒级完成。\n");
        if (sh->flags & 16)
            out(L"    WS_EX_TOPMOST：系统升 Band 时顺手加的置顶位已按窗口原状回滚（改 Band 不动置顶）。\n");
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
            out(L"\n❌ 静默扫描未在 explorer 内存中找到语义匹配的候选 key（全程零按键/零焦点变化）。\n"
                L"   可选方案:\n"
                L"   · 加 --induce 重试：允许在 explorer 内诱导一次 IAM 调用（任务栏焦点会抖一下）\n"
                L"   · 或不带 --direct 用蹦床模式（需要触发一次 explorer 的 band 调用）\n");
        else if (sh->error == 1006)
            out(L"\n❌ 执行阶段被看门狗接管（30 秒无进展）：目标窗口疑似被系统挂起\n"
                L"   （后台 UWP 应用冻结线程是典型情况）。payload 主循环已自动复位，可换目标重试。\n");
        else if (sh->error == 1007)
            out(L"\n❌ 常驻执行线程不存在（创建失败——极端异常）。请重启资源管理器后再装 hook。\n");
        else
            outf(L"\n❌ direct 失败: EnableIAM 层报错, err=%d\n", sh->error);
        colorPop();
    }

    if (g_debug) CrashBoxReport();   // 若过程中有 payload 线程被冻结，晒出来（--debug 专属）

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
    out(L"用法:\n"
        L"    bandedit-x64                            只装载 hook（注入 payload 到 explorer 后退出，日常先跑这条）\n"
        L"    bandedit-x64 [--debug] <命令> ...       --debug: 铺崩溃黑匣子 + 打印 payload 遥测（可放任意位置）\n"
        L"\n  找窗口:\n"
        L"    bandedit scan [--all]                   按 Band 分组绘制层级地图\n"
        L"    bandedit list [子串]                    平铺列出顶层窗口(含hwnd)\n"
        L"    bandedit pick                           鼠标取窗(悬停预览, F8 捕获, Esc 退出)\n"
        L"    bandedit band <hwnd|pick>               查询窗口的 Z-Band\n"
        L"  修改:\n"
        L"    bandedit set <hwnd|pick|me> <zbid 0~18> [选项]\n"
        L"        默认 direct 直调: 静默扫描 explorer 内存取 IAM key 后调 SetWindowBand,\n"
        L"                        零按键/零焦点变化; key 缓存后毫秒级完成\n"
        L"                        （改 Band 不动置顶位：系统顺带的 WS_EX_TOPMOST 会自动回滚）\n"
        L"        --trampoline  回退蹦床模式: 劫持 explorer 一次 band 调用(需触发; 加 --manual 手动按 Win)\n"
        L"        --induce      direct 扫描未命中时允许诱导一次 IAM 调用(任务栏焦点会抖一下)\n"
        L"        --dll 路径    (调试)用外部 payload DLL 覆盖内嵌版\n"
        L"    bandedit top|bottom|topmost|notopmost <hwnd|pick>\n"
        L"                                            Band 内 Z 序微调\n"
        L"  维护:\n"
        L"    bandedit unload                         卸载 explorer 内的 hook/映像(自裁)\n"
        L"    bandedit crashbox [clear]               查看/清空 payload 黑匣子(需先 --debug 跑过一次)\n"
        L"\n  例: bandedit-x64                 (装载 hook)\n"
        L"      bandedit-x64 set me 16       (测试窗口静默送入 ZBID_SYSTEM_TOOLS)\n"
        L"      bandedit-x64 set pick 16     (鼠标点一个窗口送进去)\n"
        L"      bandedit-x64 --debug set me 16   (带黑匣子/遥测的诊断跑法)\n\n");
}

// ================== 共享块生命周期小助手 ==================
struct ShareCtx { HANDLE hMap = nullptr; ShareBlock* sh = nullptr; };
static ShareCtx OpenShareCtx() {
    ShareCtx c;
    c.hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                0, sizeof(ShareBlock), kShareName);
    if (!c.hMap) {
        // v6.1 兼容回退：旧世代共享块(更小)存在时 CreateFileMapping 会因尺寸不合失败
        // → 整段打开旧块（不足页的尾部读零），跨版本的 ver 检查与 unload 仍可用。
        c.hMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, kShareName);
        if (!c.hMap) { outf(L"CreateFileMapping 失败: err=%d\n", GetLastError()); return c; }
        c.sh = (ShareBlock*)MapViewOfFile(c.hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (!c.sh || c.sh->magic != kMagic) {
            out(L"旧共享块无法识别，忽略。\n");
            if (c.sh) UnmapViewOfFile(c.sh);
            CloseHandle(c.hMap); c.sh = nullptr; c.hMap = nullptr; return c;
        }
        return c;   // 旧世代段：只读写公共前缀字段，ver<kNeedVer 由上层拦截
    }
    bool fresh = GetLastError() != ERROR_ALREADY_EXISTS;
    c.sh = (ShareBlock*)MapViewOfFile(c.hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ShareBlock));
    if (!c.sh) { out(L"MapViewOfFile 失败\n"); CloseHandle(c.hMap); c.hMap = nullptr; return c; }
    if (fresh) ZeroMemory(c.sh, sizeof(*c.sh));
    c.sh->magic = kMagic;
    return c;
}
static void CloseShareCtx(ShareCtx& c) {
    if (c.sh)   UnmapViewOfFile(c.sh);
    if (c.hMap) CloseHandle(c.hMap);
    c.sh = nullptr; c.hMap = nullptr;   // 对象续命靠 payload 持有的 g_hMap；客户端随退随关
}

// ============================ 裸启动：只装载 hook ============================
static int CmdLoad(ShareBlock* sh) {
    out(L"\n==== BandEdit：装载 hook（注入 payload 到 explorer，不执行层级操作）====\n");
    out(L"⚠️ 将注入 explorer.exe，仅限自己机器研究用途。\n\n");
    if (!EnsurePayloadResident(L"", sh)) return 1;
    out(L"\n✅ hook 已装载。之后随时：\n"
        L"   bandedit-x64 set <hwnd|pick|me> <zbid 0~18>   （默认 direct 直调，零按键/零焦点）\n"
        L"   bandedit-x64 scan / list / pick / band ...    （查询类随时可用，无需注入）\n"
        L"   bandedit-x64 unload                           （卸载并自裁释放）\n"
        L"   提示：装载后首次 set 会自动静默扫描 IAM key（约 1~2 秒），之后毫秒级。\n");
    return 0;
}

int wmain(int argc, wchar_t** argv) {
#ifndef _WIN64
    out(L"错误：必须以 64 位编译运行。\n");
    return 1;
#endif
    pGetWindowBand = (PFN_GetWindowBand)(void*)GetProcAddress(
        GetModuleHandleW(L"user32.dll"), "GetWindowBand");

    // 全局开关 --debug：可出现在任意位置（铺崩溃黑匣子 + 遥测输出），先剥离掉
    std::vector<std::wstring> a;
    for (int i = 1; i < argc; ++i) {
        if (!wcscmp(argv[i], L"--debug")) g_debug = true;
        else a.emplace_back(argv[i]);
    }

    if (a.empty()) {                        // ★ 不带命令 = 只装载 hook
        ShareCtx c = OpenShareCtx(); if (!c.sh) return 1;
        int rc = CmdLoad(c.sh);
        CloseShareCtx(c);
        return rc;
    }

    const std::wstring& cmd = a[0];

    if (cmd == L"crashbox") {           // 黑匣子读取/清空（无需注入）
        if (a.size() >= 2 && a[1] == L"clear") {
            CrashBox* cb = nullptr;
            HANDLE h = OpenCrashBox(false, &cb);
            if (!h || !cb) { out(L"没有黑匣子记录。\n"); return 0; }
            ZeroMemory(cb, sizeof(*cb)); cb->magic = kCrashMagic;
            UnmapViewOfFile(cb); CloseHandle(h);
            out(L"黑匣子已清空。\n");
            return 0;
        }
        // 区分"黑匣子对象不存在"（没人持有：未注入或已断链）与"在位但没抓到异常"
        CrashBox* probe = nullptr;
        HANDLE hp = OpenCrashBox(false, &probe);
        if (!hp) {
            out(L"黑匣子不在（未铺过黑匣子 —— 如需诊断请带 --debug 运行，例如 bandedit-x64 --debug set me 16）。\n");
        } else {
            UnmapViewOfFile(probe); CloseHandle(hp);
            if (!CrashBoxReport()) out(L"黑匣子在位，无异常记录。\n");
        }
        return 0;
    }
    if (cmd == L"scan") { CmdScan(!(a.size() >= 2 && a[1] == L"--all")); return 0; }
    if (cmd == L"list") { CmdList(a.size() >= 2 ? a[1].c_str() : nullptr); return 0; }
    if (cmd == L"pick") { PickInteractive(true); return 0; }
    if (cmd == L"band") {
        if (a.size() < 2) { Usage(); return 1; }
        HWND h = ResolveTarget(a[1].c_str());
        if (!h) { out(L"未选择窗口。\n"); return 1; }
        out(L"\n");
        PrintWindowInfo(h);
        return 0;
    }
    if (cmd == L"top" || cmd == L"bottom" || cmd == L"topmost" || cmd == L"notopmost") {
        if (a.size() < 2) { Usage(); return 1; }
        HWND h = ResolveTarget(a[1].c_str());
        if (!h) { out(L"未选择窗口。\n"); return 1; }
        CmdZop(cmd.c_str(), h);
        return 0;
    }

    if (cmd != L"set" && cmd != L"unload") { Usage(); return 1; }

    ShareCtx c = OpenShareCtx();
    if (!c.sh) return 1;

    if (cmd == L"unload") {
        HANDLE m = OpenMutexW(SYNCHRONIZE, FALSE, kMutexName);
        if (!m) { out(L"payload 未驻留，无需卸载。\n"); CloseShareCtx(c); return 0; }
        CloseHandle(m);
        InterlockedExchange(&c.sh->state, 9);
        out(L"已请求卸载：payload 将摘除 hook 并自我释放。\n");
        CloseShareCtx(c);
        return 0;
    }

    // ---- set ----（默认 direct 直调；--trampoline 回退）
    std::wstring targetArg, bandArg, dllArg;
    bool manual = false, direct = true, induce = false;
    for (size_t i = 1; i < a.size(); ++i) {
        if (a[i] == L"--manual") manual = true;
        else if (a[i] == L"--direct") { /* 默认已是 direct，兼容旧习惯写法 */ }
        else if (a[i] == L"--trampoline") direct = false;
        else if (a[i] == L"--induce") induce = true;
        else if (a[i] == L"--dll" && i + 1 < a.size()) dllArg = a[++i];
        else if (targetArg.empty()) targetArg = a[i];
        else if (bandArg.empty())   bandArg = a[i];
    }
    if (targetArg.empty() || bandArg.empty()) { Usage(); CloseShareCtx(c); return 1; }
    DWORD band = wcstoul(bandArg.c_str(), nullptr, 0);
    if (band > 18) { out(L"zbid 应在 0~18 之间\n"); CloseShareCtx(c); return 1; }

    out(L"\n==== BandEdit v6.2 —— set (借 explorer 调 SetWindowBand) ====\n");
    out(L"⚠️ 将注入/使用 explorer.exe，仅限自己机器研究用途。\n");
    if (g_debug) CrashBoxReport();   // 上次若抓到过异常，先把记录晒出来（--debug 专属）
    if (direct)
        outf(L"模式: direct 直调（静默扫描取 IAM key，零按键/零焦点%s）\n\n",
             induce ? L"；扫描未命中时允许诱导兜底" : L"");
    else
        out(L"模式: trampoline（劫持 explorer 的调用，需触发一次）\n\n");
    int rc = CmdSet(targetArg, band, manual, direct, induce, dllArg, c.sh);
    CloseShareCtx(c);
    return rc;
}
