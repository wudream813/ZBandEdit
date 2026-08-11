// ============================================================================
// bandpayload.cpp v5.1 —— 注入 explorer.exe 的载荷 DLL（CRT-free + 手动映射专用）
//
//   v5.1 关键改动：彻底去掉 CRT —— 以 -nostdlib 编译、入口直接是我们的 DllMain。
//   手动映射跳过了系统加载器，正常 LoadLibrary 时 mingw CRT 入口 (DllMainCRTStartup)
//   里有一大段依赖"加载器已注册该模块"的初始化；实测这段在手动映射下会让宿主进程
//   直接崩溃（explorer 重启）。不要它才是最好的免疫：
//     · 无 CRT 初始化 → 无 TLS 目录回调依赖、无安全 cookie 初始化依赖
//     · 仅有的几个 C 运行时小函数（memcpy/memset/...）自给自足
//     · 导入只剩 kernel32.dll / user32.dll
//
//   手动映射约定（客户端实现的迷你加载器，见 bandedit.cpp ManualMapImage）：
//   修重定位→解析导入→按节保护→注册 .pdata→(若有)TLS 回调→调 DllMain(ATTACH, 卸载桩)
//     DllMain(lpvReserved) = 客户端在 explorer 内准备的"自裁桩"地址：
//         VirtualFree(自身映像基址, MEM_RELEASE) + RtlExitUserThread(0)，不返回。
//
//   模式1 (trampoline): inline hook user32!SetWindowBand，借 explorer 调用换参数
//   模式2 (direct)    : IAM key 静默扫描（默认零按键/零焦点）/ --induce 诱导兜底
//
// 编译（CRT-free）:
//   g++ -std=c++17 -O2 -shared -nostdlib -ffreestanding -fno-exceptions -fno-rtti \
//       -fno-stack-protector -fno-stack-check -Wl,-e,DllMain \
//       -o bandedit-payload-x64.dll bandpayload.cpp -lkernel32 -luser32
//
// ⚠️ 仅限自己机器研究用途。
// ============================================================================
#include <windows.h>
#include <tlhelp32.h>

// ---- CRT-free：自给自足的几个 C 运行时函数 --------------------------------------
// 编译器即便 -fno-builtin 也可能为结构体拷贝/清零合成 memcpy/memset 调用 —— 必须提供。
extern "C" {
void* __cdecl memcpy(void* d, const void* s, size_t n) {
    BYTE* D = (BYTE*)d; const BYTE* S = (const BYTE*)s;
    for (size_t i = 0; i < n; ++i) D[i] = S[i];
    return d;
}
void* __cdecl memmove(void* d, const void* s, size_t n) {
    BYTE* D = (BYTE*)d; const BYTE* S = (const BYTE*)s;
    if (D < S) for (size_t i = 0; i < n; ++i) D[i] = S[i];
    else       for (size_t i = n; i > 0; --i) D[i-1] = S[i-1];
    return d;
}
void* __cdecl memset(void* d, int c, size_t n) {
    BYTE* D = (BYTE*)d;
    for (size_t i = 0; i < n; ++i) D[i] = (BYTE)c;
    return d;
}
int __cdecl memcmp(const void* a, const void* b, size_t n) {
    const BYTE* A = (const BYTE*)a; const BYTE* B = (const BYTE*)b;
    for (size_t i = 0; i < n; ++i) if (A[i] != B[i]) return A[i] < B[i] ? -1 : 1;
    return 0;
}
} // extern "C"

// wcsstr 的本地实现（原 msvcrt 版本随 CRT 一同裁掉了）
static const wchar_t* FindSubW(const wchar_t* h, const wchar_t* n) {
    for (; *h; ++h) {
        const wchar_t* p = h; const wchar_t* q = n;
        while (*p && *q && *p == *q) { ++p; ++q; }
        if (!*q) return h;
    }
    return nullptr;
}

// 版本标识（嵌在二进制里，工具/客户端可扫字节识别载荷版本）
extern "C" volatile const char kPayloadIdent[] = "BANDPAYLOAD_VER=14";

// ---- 与客户端共享的通信块 (Local\ZBandHookShareV1) ---------------------------
// state: 0=空闲 1=请求 2=成功 3=调用被拒 5=hook安装失败 6=direct失败 7=诱导捕获中 8=静默扫描中 9=卸载
// flags(payload→client): bit0 已捕获key bit1 无#2510 bit2 本次direct执行 bit3 key来自静默扫描 bit4 已回滚顺带TOPMOST
// reserved[0](client→payload) = 请求标志: 1=SILENT(只扫描, 禁止诱导/焦点/输入)
struct ShareBlock {
    volatile LONG      state;
    LONG               pad;
    unsigned long long hwnd;
    unsigned long long insertAfter;
    DWORD              band;
    DWORD              result;
    DWORD              error;
    DWORD              magic;     // 'ZBND'
    DWORD              ver;       // payload 协议版本 = 5
    DWORD              mode;      // 0 = trampoline, 1 = direct
    DWORD              flags;
    DWORD              reserved[6];   // [0]=SILENT入参 [1]=相位镜像 [2]=心跳戳(GetTickCount) [3]=最近state
    // ---- v14(v6.1) 追加：免 --debug 的法医字段 --------------------------------
    volatile LONG      loopCount;     // 主循环圈数（与心跳戳互证活性；转=活着）
    DWORD              workerTid;     // 主循环线程 TID（客户端 OpenThread 探死活）
    DWORD              execTid;       // 常驻执行线程 TID
    DWORD              deathTid;      // VEH 冻结线程 TID（0=天下太平）——最后写，充当提交标志
    DWORD              deathCode;     //        异常码
    DWORD              deathPhase;    //        相位
    DWORD              deathPadA;     //        对齐占位（保持 ULONGLONG 8B 对齐、双端布局确定）
    DWORD              deathPadB;
    DWORD              deathPadC;
    ULONGLONG          deathRip;      //        现场：RIP（配 deathBase 算 RVA）
    ULONGLONG          deathRsp;
    ULONGLONG          deathAux;      //        AV 时的目标地址
    ULONGLONG          deathBase;     //        我们的映像基址
};

static const wchar_t* kShareName = L"Local\\ZBandHookShareV1";
static const wchar_t* kMutexName = L"Local\\ZBandHookPayloadReadyV1";
static const DWORD    kMagic     = 0x444E425A;   // 'ZBND'
static const DWORD    kProtoVer  = 14;  // v6.1: 死亡笔记/TID探针/圈数直写共享块（免 --debug 法医）
static const DWORD    RF_SILENT  = 1;

static HMODULE     g_self   = nullptr;
static HANDLE      g_hMap   = nullptr;
static ShareBlock* g_share  = nullptr;
static HANDLE      g_ready  = nullptr;
// 自裁桩（手动映射卸载用）：() -> 不返回 [VirtualFree(自身)+RtlExitUserThread]
static void (*volatile g_selfDestruct)(void) = nullptr;

// ---- 黑匣子（崩溃记录器，诊断用）------------------------------------------------
// 客户端在注入前创建 Local\ZBandCrashBoxV1；我们装入 VEH：
// 任何线程一旦异常 → 记录 ExceptionCode/RIP/寄存器/目标地址/阶段相位 →
// 冻结故障线程（不返回、不让异常升级为进程崩溃）→ explorer 存活，client 可读取。
struct CrashBox {
    DWORD     magic;      // 'XBX1' = 0x31584258
    DWORD     caught;     // 0→1：已捕获
    DWORD     code;       // ExceptionCode
    DWORD     phase;      // 阶段相位（见各处 g_phase 赋值注释）
    DWORD     tid;
    DWORD     pad;
    ULONGLONG rip, rsp;
    ULONGLONG rax, rbx, rcx, rdx, r8;
    ULONGLONG base;       // 我们的映像基址（现场换算 RVA 用）
    ULONGLONG faultAddr;  // 访问违例的目标地址（NumberParameters>=2 时）
    // ---- v5.3 活埋式遥测（无异常也持续更新；前缀布局与 XBX1 兼容的追加） ----
    ULONGLONG beats;      // Worker 主循环心跳（每圈 +1）
    DWORD     stateSeen;  // 主循环最近一次读到的 share->state
    DWORD     auxPad;
    ULONGLONG aux;        // 通用实况：扫描推进的内存地址等
};
static const wchar_t* kCrashBoxName = L"Local\\ZBandCrashBoxV1";
static const DWORD    kCrashMagic   = 0x31584258;   // 'XBX1'
static CrashBox* volatile g_cb = nullptr;
static HANDLE             g_cbHandle = nullptr;  // 常驻持有：命名对象随最后一个句柄销毁，只留视图保不住它
static volatile DWORD     g_phase = 0;
static PVOID              g_veh = nullptr;   // 本进程内自装的 VEH 句柄（卸载时能摘除）

// 黑匣子共享页（客户端在注入前创建）；装载顺序无关：引导壳可能先于 DllMain 让我跑
// ⚠️ 成功链接后句柄常驻持有（g_cbHandle）——命名对象随最后一个句柄销毁；
//    只留视图的话客户端一退出对象就没了，g_cb 会退化成指向无名孤页的野映射。
static void LinkCrashBox() {
    if (g_cb) return;
    HANDLE h = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, kCrashBoxName);
    if (h) {
        void* v = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(CrashBox));
        if (v && ((CrashBox*)v)->magic == kCrashMagic) { g_cb = (CrashBox*)v; g_cbHandle = h; }
        else { if (v) UnmapViewOfFile(v); CloseHandle(h); }
    }
}
// 导出给引导壳点名安装（dllexport → 客户端查导出表拿 RVA）
extern "C" __declspec(dllexport) LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ep) {
    auto er = ep->ExceptionRecord;
    // ⚠️ 只按"致命白名单"记录+冻结；其余一律放行。
    //    0x40010006(OutputDebugString) 是良性通知；0xE06D7363 是 MSVC C++ EH —
    //    Windows 内部大量组件拿它当控制流用、随后自己 catch，我们必须让它继续走、
    //    否则会冻住无辜的系统线程（v5.4 实测因此冻结过 explorer 线程并疑似引发重启）。
    switch (er->ExceptionCode) {
    case 0xC0000005u:  // EXCEPTION_ACCESS_VIOLATION
    case 0xC00000FDu:  // EXCEPTION_STACK_OVERFLOW
    case 0xC000001Du:  // EXCEPTION_ILLEGAL_INSTRUCTION
    case 0xC0000094u:  // EXCEPTION_INT_DIVIDE_BY_ZERO
    case 0xC0000374u:  // STATUS_HEAP_CORRUPTION
    case 0xC0000409u:  // STATUS_STACK_BUFFER_OVERRUN / fail fast
        break;
    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // v6.1 死亡笔记：只要共享块在手就记录（不再依赖 --debug 黑匣子在场）。
    // 谁被冻结、死在什么码上、RIP/相位 —— 客户端探活时直接读。deathTid 最后写=提交标志。
    if (g_share && g_share->magic == kMagic && !g_share->deathTid) {
        g_share->deathCode  = er->ExceptionCode;
        g_share->deathPhase = g_phase;
        g_share->deathRip   = ep->ContextRecord->Rip;
        g_share->deathRsp   = ep->ContextRecord->Rsp;
        g_share->deathAux   = (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
                               er->NumberParameters >= 2) ? er->ExceptionInformation[1] : 0;
        g_share->deathBase  = (ULONGLONG)(uintptr_t)g_self;
        InterlockedExchange((volatile LONG*)&g_share->deathTid, (LONG)GetCurrentThreadId());
    }
    if (!g_cb) LinkCrashBox();
    if (g_cb && g_cb->magic == kCrashMagic && !g_cb->caught) {
        auto cx = ep->ContextRecord;
        g_cb->code  = er->ExceptionCode;
        g_cb->phase = g_phase;
        g_cb->rip = cx->Rip; g_cb->rsp = cx->Rsp;
        g_cb->rax = cx->Rax; g_cb->rbx = cx->Rbx; g_cb->rcx = cx->Rcx;
        g_cb->rdx = cx->Rdx; g_cb->r8  = cx->R8;
        g_cb->base = (ULONGLONG)(uintptr_t)g_self;
        g_cb->faultAddr = (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
                           er->NumberParameters >= 2) ? er->ExceptionInformation[1] : 0;
        g_cb->tid = GetCurrentThreadId();
        g_cb->caught = 1;
    }
    for (;;) Sleep(60000);            // 冻结故障线程，explorer 存活；重启 explorer 即清场
}
static void InstallCrashBox() {
    g_veh = AddVectoredExceptionHandler(1, &CrashHandler);            // 第一优先；句柄留存自卸可摘
    LinkCrashBox();
}
// 相位推进宏：同步镜像进黑匣子（已链接时）→ 客户端 crashbox 随时看得到 payload 在哪一步
#define PHASE(n) do { g_phase = (DWORD)(n); if (g_cb) g_cb->phase = (DWORD)(n); } while (0)
using PFN_SetWindowBand = BOOL (WINAPI*)(HWND, HWND, DWORD);
using PFN_EnableIAM     = BOOL (WINAPI*)(ULONG64 key, BOOL enable);

static PFN_SetWindowBand g_realSWB = nullptr;   // user32!SetWindowBand
static PFN_EnableIAM     g_realIAM = nullptr;   // user32.dll 仅序号导出 #2510

// ---- 12 字节 inline hook 基建 ------------------------------------------------
static CRITICAL_SECTION g_cs;
static BYTE  g_origSWB[12];
static BYTE  g_origIAM[12];
static bool  g_swbHooked = false;
static bool  g_iamHooked = false;
static DWORD g_callErr   = 0;

static void Write12(void* target, const BYTE* src) {
    DWORD old = 0;
    VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &old);
    memcpy(target, src, 12);
    VirtualProtect(target, 12, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, 12);
}
static void MakeJump(BYTE out12[12], void* detour) {
    BYTE j[12] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };  // mov rax,det; jmp rax
    memcpy(&j[2], &detour, 8);
    memcpy(out12, j, 12);
}

static BOOL WINAPI Detour_SWB(HWND, HWND, DWORD);
static BOOL WINAPI Detour_IAM(ULONG64, BOOL);

static bool HookSWBInstall() {
    if (!g_realSWB || g_swbHooked) return g_realSWB != nullptr;
    BYTE j[12]; MakeJump(j, (void*)&Detour_SWB);
    memcpy(g_origSWB, (const void*)g_realSWB, 12);
    Write12((void*)g_realSWB, j);
    g_swbHooked = true;
    return true;
}
static void HookSWBRemove() { if (g_realSWB && g_swbHooked) { Write12((void*)g_realSWB, g_origSWB); g_swbHooked = false; } }

static bool HookIAMInstall() {
    if (!g_realIAM || g_iamHooked) return g_realIAM != nullptr;
    BYTE j[12]; MakeJump(j, (void*)&Detour_IAM);
    memcpy(g_origIAM, (const void*)g_realIAM, 12);
    Write12((void*)g_realIAM, j);
    g_iamHooked = true;
    return true;
}
static void HookIAMRemove() { if (g_realIAM && g_iamHooked) { Write12((void*)g_realIAM, g_origIAM); g_iamHooked = false; } }

static BOOL CallRealSWB(HWND h, HWND a, DWORD b) {
    EnterCriticalSection(&g_cs);
    HookSWBRemove();
    SetLastError(0);
    BOOL r = g_realSWB(h, a, b);
    g_callErr = r ? 0 : GetLastError();
    HookSWBInstall();
    LeaveCriticalSection(&g_cs);
    return r;
}
static BOOL CallRealIAM(ULONG64 key, BOOL enable) {
    EnterCriticalSection(&g_cs);
    HookIAMRemove();
    SetLastError(0);
    BOOL r = g_realIAM(key, enable);
    g_callErr = r ? 0 : GetLastError();
    HookIAMInstall();
    LeaveCriticalSection(&g_cs);
    return r;
}

// ---- SetWindowBand 副产物回滚 -----------------------------------------------------
// win32k 在把窗口抬进高于桌面的 Band 时会顺手加 WS_EX_TOPMOST（内核实证：
// 显式 SetWindowPos(HWND_NOTOPMOST) 也撕不掉 —— 高于桌面的 Band 该位是强制的）。
// 所以只在"降回 Band<=1 恢复普通窗口"时回滚才有意义：把残留的置顶位摘掉。
// ⚠️ 必须带 SWP_NOSENDCHANGING：默认 SetWindowPos 会向目标同步投递
//    WM_WINDOWPOSCHANGED，撞上被系统挂起的窗口（后台 UWP 等）会永久阻塞。
static void RestoreTopmostIfAdded(HWND h, LONG_PTR exBefore, DWORD newBand) {
    if (newBand > 1) return;                                    // Band>桌面：强制位，纯装饰，不浪费动作
    if (exBefore & WS_EX_TOPMOST) return;                       // 本来就置顶 → 完全别动
    if (!h || !(GetWindowLongPtrW(h, GWL_EXSTYLE) & WS_EX_TOPMOST)) return;
    SetWindowPos(h, HWND_NOTOPMOST, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_NOSENDCHANGING);
    if (g_share && g_share->magic == kMagic)
        InterlockedOr((volatile LONG*)&g_share->flags, 16);     // bit4: 已回滚顺带的 TOPMOST
}

// ---- 状态：trampoline 请求 ----------------------------------------------------
static volatile bool      g_armed = false;
static volatile uintptr_t g_tHwnd  = 0;
static volatile uintptr_t g_tAfter = 0;
static volatile DWORD     g_tBand   = 0;

// ---- 状态：direct 请求 --------------------------------------------------------
static volatile ULONG64  g_iamKey   = 0;
static volatile bool     g_haveKey  = false;
static uintptr_t         g_qHwnd    = 0;
static uintptr_t         g_qAfter   = 0;
static DWORD             g_qBand    = 0;
static bool              g_directPending = false;
static int               g_induceRounds  = 0;
static bool              g_reqSilent     = false;

// trampoline 劫持 detour：仅 armed 时替换一次参数
static BOOL WINAPI Detour_SWB(HWND hWnd, HWND hAfter, DWORD dwBand) {
    EnterCriticalSection(&g_cs);
    HWND h = hWnd; HWND a = hAfter; DWORD b = dwBand;
    bool hijack = false;
    if (g_armed) {
        h = (HWND)g_tHwnd; a = (HWND)g_tAfter; b = g_tBand;
        g_armed = false;
        hijack  = true;
    }
    HookSWBRemove();
    LONG_PTR exBefore = hijack ? GetWindowLongPtrW(h, GWL_EXSTYLE) : 0;
    SetLastError(0);
    BOOL ret = g_realSWB(h, a, b);
    DWORD err = ret ? 0 : GetLastError();
    HookSWBInstall();
    if (hijack && ret) RestoreTopmostIfAdded(h, exBefore, b);
    if (hijack && g_share && g_share->magic == kMagic) {
        g_share->result = (DWORD)ret;
        g_share->error  = err;
        InterlockedAnd((volatile LONG*)&g_share->flags, ~4L);
        InterlockedExchange(&g_share->state, ret ? 2 : 3);
    }
    LeaveCriticalSection(&g_cs);
    return ret;
}

// IAM key 嗅探 detour：先放行真实调用，仅当成功且 enable=TRUE 才记录 key
static BOOL WINAPI Detour_IAM(ULONG64 key, BOOL enable) {
    BOOL ret = CallRealIAM(key, enable);
    if (ret && enable && key && !g_haveKey) {
        g_iamKey  = key;
        g_haveKey = true;
        if (g_share && g_share->magic == kMagic)
            InterlockedOr((volatile LONG*)&g_share->flags, 1);
    }
    return ret;
}

// ---- 【A 通道】静默内存扫描 + 预言机验证 ----------------------------------------
// 候选验证：错误的 key 只会失败无副作用（实测 err=87），命中即开通。
// 扫描期间摘除 IAM hook（我们自己的循环里直接调真实函数，省掉每候选一次
// VirtualProtect/FlushInstructionCache 的开销）。
static volatile LONG g_scanAbort = 0;

static bool VerifyCandidateRaw(ULONG64 cand, ULONG64* found) {   // 调用方须已摘除 hook
    if (cand < 0x10000) return false;               // 过滤小整数（key 是 64 位随机值）
    SetLastError(0);
    if (g_realIAM(cand, TRUE)) {
        g_realIAM(cand, FALSE);
        *found = cand;
        return true;
    }
    return false;
}

static bool ScanRangeRaw(const BYTE* base, SIZE_T size, ULONG64* found, SIZE_T* budget) {
    for (SIZE_T off = 0; off + 8 <= size; off += 8) {
        if (budget && !*budget) return false;       // 预算耗尽（防极端情况长时间占用）
        if (budget) --*budget;
        if ((off & 0x3FFFF) == 0) {
            if (g_cb) g_cb->aux = (ULONGLONG)(uintptr_t)(base + off);   // 扫描推进地址实况
            if (InterlockedCompareExchange(&g_scanAbort, 0, 0)) return false;
        }
        ULONG64 v = *(const ULONG64*)(base + off);
        if (VerifyCandidateRaw(v, found)) return true;
    }
    return false;
}

// 扫描单个内存区域（带 VirtualQuery 验证可访问性）
static bool ScanVirtualRange(const BYTE* base, SIZE_T size, ULONG64* found, SIZE_T* budget) {
    const BYTE* p = base;
    const BYTE* end = base + size;
    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(p, &mbi, sizeof(mbi)) || mbi.RegionSize == 0) break;
        SIZE_T chunk = mbi.RegionSize - ((SIZE_T)p - (SIZE_T)mbi.BaseAddress);
        if (chunk > (SIZE_T)(end - p)) chunk = (SIZE_T)(end - p);
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_READONLY))) {
            if (ScanRangeRaw(p, chunk, found, budget)) return true;
        }
        p += chunk;
        if (budget && !*budget) break;
    }
    return false;
}

// 扫描已加载模块的可写节（twinui 相关模块优先）
static bool ScanModulesRaw(bool twinuiOnly, ULONG64* found, SIZE_T* budget) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    for (BOOL ok = Module32FirstW(snap, &me); ok && !(budget && !*budget); ok = Module32NextW(snap, &me)) {
        bool twin = FindSubW(me.szModule, L"twinui") || FindSubW(me.szModule, L"TwinUI") ||
                    FindSubW(me.szModule, L"pcshell");
        if (twinuiOnly != twin) continue;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)me.modBaseAddr;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        auto nt = (IMAGE_NT_HEADERS64*)(me.modBaseAddr + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (!(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
            SIZE_T size = sec[i].Misc.VirtualSize;
            if (!size || size > 8 * 1024 * 1024) size = 8 * 1024 * 1024;
            if (ScanVirtualRange(me.modBaseAddr + sec[i].VirtualAddress, size, found, budget)) {
                CloseHandle(snap);
                return true;
            }
        }
    }
    CloseHandle(snap);
    return false;
}

// 通道 A 主入口：twinui .data → 其他模块可写节 → 全进程私有 RW（带字节预算）
static bool AcquireKeyByScan() {
    if (!g_realIAM) return false;
    ULONG64 found = 0;
    InterlockedExchange(&g_scanAbort, 0);

    EnterCriticalSection(&g_cs);
    HookIAMRemove();                       // 整个扫描窗口内直调真实函数

    SIZE_T budget = 6ull * 1024 * 1024;    // 最多验证 ~600 万个候选（最坏 ~几秒；实测命中远早于此）
    bool ok = ScanModulesRaw(true,  &found, &budget)   // 先 twinui/pcshell 可写节
           || ScanModulesRaw(false, &found, &budget);  // 再其他模块可写节

    // 兜底：私有堆内存（预算内）
    if (!ok && budget) {
        ULONG_PTR p = 0;
        MEMORY_BASIC_INFORMATION mbi{};
        while (p < 0x00007FFFFFFFFFFFull &&
               VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE &&
                mbi.Type == MEM_PRIVATE) {
                SIZE_T chunk = mbi.RegionSize;
                if (chunk > budget) chunk = budget;
                if (ScanRangeRaw((const BYTE*)mbi.BaseAddress, chunk, &found, &budget)) {
                    ok = true;
                    break;
                }
            }
            if (!budget) break;
            p = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
    }

    HookIAMInstall();
    LeaveCriticalSection(&g_cs);

    if (ok) {
        g_iamKey  = found;
        g_haveKey = true;
        if (g_share && g_share->magic == kMagic)
            InterlockedOr((volatile LONG*)&g_share->flags, 1 | 8);   // bit3: key 来自扫描
    }
    return ok;
}

// ---- 【B 通道】焦点诱导（--induce 兜底） ----------------------------------------
static void InduceExplorerIAM() {
    HWND hFore = GetForegroundWindow();
    HWND hTray = FindWindowW(L"Shell_TrayWnd", nullptr);
    HWND hDesk = GetDesktopWindow();
    if (hTray && hDesk) {
        for (int i = 0; i < 3 && !g_haveKey; ++i) {
            if (i > 0) {
                AllocConsole();
                HWND hc = GetConsoleWindow();
                if (hc) SetWindowPos(hc, nullptr, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
                FreeConsole();
            }
            SetForegroundWindow(hDesk);
            Sleep(100);
            SetForegroundWindow(hTray);
            Sleep(100);
            if (hFore) SetForegroundWindow(hFore);
            Sleep(150);
        }
    }
    for (int i = 0; i < 2 && !g_haveKey; ++i) {
        INPUT in{};
        in.type = INPUT_KEYBOARD;
        in.ki.wVk = VK_LCONTROL;
        SendInput(1, &in, sizeof(in));
        Sleep(60);
        for (int j = 0; j < 2 && !g_haveKey; ++j) {
            INPUT e{};
            e.type    = INPUT_KEYBOARD;
            e.ki.wVk  = VK_ESCAPE;
            SendInput(1, &e, sizeof(e));
            Sleep(60);
            e.ki.dwFlags = KEYEVENTF_KEYUP;
            SendInput(1, &e, sizeof(e));
            Sleep(60);
        }
        in.ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(1, &in, sizeof(in));
        Sleep(400);
    }
}

// 在本线程开通 IAM 并直接执行 SetWindowBand
static void MarkExec(DWORD);   // 前置声明：实体在"常驻执行线程"小节
static void TryExecDirect() {
    if (!g_share) return;
    if (!g_realIAM) {
        g_share->error  = 1001;
        g_share->result = 0;
        InterlockedOr((volatile LONG*)&g_share->flags, 2 | 4);
        InterlockedExchange(&g_share->state, 6);
        return;
    }
    MarkExec(13);
    // 1) 开通
    SetLastError(0);
    if (!CallRealIAM(g_iamKey, TRUE)) {
        g_share->result = 0;
        g_share->error  = g_callErr ? g_callErr : 1002;
        InterlockedOr((volatile LONG*)&g_share->flags, 4);
        InterlockedExchange(&g_share->state, 6);
        return;
    }
    MarkExec(14);
    // 2) 直调
    SetLastError(0);
    LONG_PTR exBefore = GetWindowLongPtrW((HWND)g_qHwnd, GWL_EXSTYLE);
    MarkExec(16);
    BOOL r = CallRealSWB((HWND)g_qHwnd, (HWND)g_qAfter, g_qBand);
    MarkExec(17);
    if (r) RestoreTopmostIfAdded((HWND)g_qHwnd, exBefore, g_qBand);
    DWORD err = r ? 0 : g_callErr;
    CallRealIAM(g_iamKey, FALSE);
    MarkExec(19);

    g_share->result = (DWORD)r;
    g_share->error  = err;
    g_directPending = false;
    InterlockedOr((volatile LONG*)&g_share->flags, 4);
    InterlockedExchange(&g_share->state, r ? 2 : 3);
}

// direct 阶段推进：已key→执行；未key→先扫描，(非silent)再诱导
static bool g_scanTried = false;
static void DirectStep() {
    if (!g_share || g_share->magic != kMagic) return;   // 单一入口安全闸（也喂给 GCC 的非空证明）
    PHASE(20); MarkExec(11);
    if (g_haveKey) { PHASE(22); MarkExec(12); TryExecDirect(); return; }
    if (!g_scanTried) {
        g_scanTried = true;
        InterlockedExchange(&g_share->state, 8);          // 告诉客户端：静默扫描中
        PHASE(21); MarkExec(30);
        bool scanned = AcquireKeyByScan();
        MarkExec(31);
        if (scanned) { PHASE(22); MarkExec(12); TryExecDirect(); return; }
        if (InterlockedCompareExchange(&g_share->state, 8, 8) == 0)  // 没被客户端取消
            InterlockedExchange(&g_share->state, 7);      // 回退到"诱导"阶段
        return;
    }
    if (g_reqSilent) {                                    // 严格静默：绝不碰焦点/输入
        g_share->error  = 1005;                           // 自定义: 扫描未命中且未允许诱导
        g_share->result = 0;
        InterlockedOr((volatile LONG*)&g_share->flags, 4);
        InterlockedExchange(&g_share->state, 6);
        return;
    }
    if (g_induceRounds < 3) {
        ++g_induceRounds;
        InduceExplorerIAM();
        if (g_haveKey) TryExecDirect();
    } else {
        g_share->error  = 1003;
        g_share->result = 0;
        InterlockedOr((volatile LONG*)&g_share->flags, 4);
        InterlockedExchange(&g_share->state, 6);
    }
}

// ---- 常驻执行线程（v6.0）----------------------------------------------------------
// 演变史：v5.2 主循环同步跑（拖死水循环）→ v5.3 每请求 CreateThread（撞上加载器锁/
// 线程通知可能把主循环也拖死）→ v6.0 常驻线程 + 事件唤醒：请求路径零线程创建。
// 打点（MarkExec → reserved[4]=编号 reserved[5]=时间戳）不经主循环直写共享块：
// 就算主循环死了，客户端也能看到执行线程死在哪个数字上。
static volatile LONG  g_childBusy = 0;
static volatile DWORD g_childTick = 0;   // 起跑线（GetTickCount），主循环看门狗用
static HANDLE         g_execEvent = nullptr;

static void MarkExec(DWORD m) {
    if (g_share && g_share->magic == kMagic) {
        InterlockedExchange((volatile LONG*)&g_share->reserved[4], (LONG)m);
        InterlockedExchange((volatile LONG*)&g_share->reserved[5], (LONG)GetTickCount());
    }
}

static DWORD WINAPI ExecMain(LPVOID) {
    if (g_share && g_share->magic == kMagic) g_share->execTid = GetCurrentThreadId();   // v14: 供客户端探活
    for (;;) {
        WaitForSingleObject(g_execEvent, INFINITE);
        MarkExec(10);                                   // `me 已醒，开始处理
        for (;;) {
            DirectStep();                               // 每次推进一个阶段
            LONG st2 = g_share ? InterlockedCompareExchange(&g_share->state, 0, 0) : 0;
            if (st2 != 7 || !g_directPending) break;    // 7=诱导轮继续；其余收工
        }
        MarkExec(20);                                   // 本轮请求处理完毕
        InterlockedExchange(&g_childBusy, 0);
    }
    return 0;
}

// ---- 卸载收尾（state=9）---------------------------------------------------------
// 手动映射加载时模块未注册：不能 FreeLibrary —— 跳进客户端布好的自裁桩。
static void SelfUnloadNoReturn() {
    PHASE(90);
    if (g_veh) { RemoveVectoredExceptionHandler(g_veh); g_veh = nullptr; }  // 先摘 VEH，防悬挂
    EnterCriticalSection(&g_cs);
    HookSWBRemove();
    HookIAMRemove();
    LeaveCriticalSection(&g_cs);
    DeleteCriticalSection(&g_cs);
    if (g_cb)       { UnmapViewOfFile(g_cb); g_cb = nullptr; }
    if (g_cbHandle) { CloseHandle(g_cbHandle); g_cbHandle = nullptr; }
    if (g_share) UnmapViewOfFile(g_share);
    if (g_hMap)  CloseHandle(g_hMap);
    if (g_ready) CloseHandle(g_ready);
    void (*boom)(void) = g_selfDestruct;
    if (boom) {
        boom();            // VirtualFree(自身映像) + RtlExitUserThread —— 不返回
        __builtin_unreachable();
    }
    FreeLibraryAndExitThread(g_self, 0);   // 正常 LoadLibrary 加载时的经典卸载
}

// ---- 工作线程 -----------------------------------------------------------------
static DWORD WINAPI Worker(LPVOID) {
    PHASE(10);
    bool shareOk = false;
    for (int i = 0; i < 400; ++i) {
        g_hMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, kShareName);
        if (g_hMap) {
            g_share = (ShareBlock*)MapViewOfFile(g_hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ShareBlock));
            if (g_share && g_share->magic == kMagic) { shareOk = true; break; }
            if (g_share) { UnmapViewOfFile(g_share); g_share = nullptr; }
            CloseHandle(g_hMap); g_hMap = nullptr;
        }
        Sleep(50);
    }
    if (shareOk) PHASE(11);

    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    g_realSWB = (PFN_SetWindowBand)(void*)GetProcAddress(u32, "SetWindowBand");
    g_realIAM = (PFN_EnableIAM)(void*)GetProcAddress(u32, MAKEINTRESOURCEA(2510));
    PHASE(12);

    bool swbOk = g_realSWB && shareOk && HookSWBInstall();
    HookIAMInstall();
    PHASE(13);

    if (shareOk) {
        InterlockedExchange((volatile LONG*)&g_share->ver, kProtoVer);
        if (!swbOk)     InterlockedExchange(&g_share->state, 5);
        if (!g_realIAM) InterlockedOr((volatile LONG*)&g_share->flags, 2);
    }
    g_ready = CreateMutexW(nullptr, FALSE, kMutexName);
    // ⚠️ 不要在这里放 OutputDebugString*：它抛 0x40010006 良性异常，VEH 时代曾在此冻死 Worker
    if (!swbOk) { SelfUnloadNoReturn(); return 0; }

    // 常驻执行线程（v6.0）：请求路径只 SetEvent，绝不临时 CreateThread
    g_execEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (g_execEvent) {
        HANDLE et = CreateThread(nullptr, 0, ExecMain, nullptr, 0, nullptr);
        if (et) CloseHandle(et); else { CloseHandle(g_execEvent); g_execEvent = nullptr; }
    }

    if (g_share && g_share->magic == kMagic) g_share->workerTid = GetCurrentThreadId();  // v14: 供客户端探活
    PHASE(14);
    for (;;) {
        LONG st = InterlockedCompareExchange(&g_share->state, 0, 0);
        if (!g_cb) { static DWORD relink = 0; if ((++relink & 0x3F) == 1) LinkCrashBox(); }  // 定期重试链接黑匣子
        if (g_cb) { ++g_cb->beats; g_cb->stateSeen = (DWORD)st; }   // 心跳 + 实况转播
        // 共享块内嵌遥测（非 debug 也可用）：客户端随时可校对"主循环在不在跑/看到什么 state"
        InterlockedExchange((volatile LONG*)&g_share->reserved[1], (LONG)g_phase);
        InterlockedExchange((volatile LONG*)&g_share->reserved[2], (LONG)GetTickCount());
        InterlockedExchange((volatile LONG*)&g_share->reserved[3], (LONG)st);
        InterlockedIncrement(&g_share->loopCount);                 // v14: 圈数（与心跳戳互证）
        if (st == 0) {
            g_armed = false;
            g_directPending = false;
            g_induceRounds  = 0;
            g_scanTried     = false;
            InterlockedExchange(&g_scanAbort, 1);         // 中止可能在跑的扫描
        } else if (st == 1) {
            if (g_share->mode == 1) {
                g_qHwnd  = (uintptr_t)g_share->hwnd;
                g_qAfter = (uintptr_t)g_share->insertAfter;
                g_qBand  = g_share->band;
                g_reqSilent = (g_share->reserved[0] & RF_SILENT) != 0;
                g_directPending = true;
                g_induceRounds  = 0;
                g_scanTried     = false;
                InterlockedExchange(&g_scanAbort, 0);
                if (!InterlockedCompareExchange(&g_childBusy, 1, 0)) {   // 0→1 成功者负责派单
                    g_childTick = GetTickCount();
                    InterlockedExchange((volatile LONG*)&g_share->reserved[4], 0);   // 清空旧打点
                    if (g_execEvent) {
                        SetEvent(g_execEvent);                      // 唤醒常驻执行线程
                    } else {                                        // 常驻线程不存在（不应发生）
                        g_share->error = 1007;
                        InterlockedOr((volatile LONG*)&g_share->flags, 4);
                        InterlockedExchange(&g_share->state, 6);
                        InterlockedExchange(&g_childBusy, 0);
                    }
                }
            } else if (!g_armed) {
                g_tHwnd  = (uintptr_t)g_share->hwnd;
                g_tAfter = (uintptr_t)g_share->insertAfter;
                g_tBand  = g_share->band;
                g_armed  = true;
            }
        } else if (st == 7) {
            // 诱导多轮由执行线程内部自推；主循环只旁观 + 心跳
        } else if (st == 9) {
            break;
        }
        // 看门狗：执行子线程失联（典型：撞上被系统挂起的目标窗口，同步消息死等）
        // → 报 1006 并放生，避免 g_childBusy 卡死导致之后所有请求派不出去。
        // 只在 state 仍是 1（执行段）时接管；7/8 说明扫描/诱导正常推进中，不打扰。
        if (InterlockedCompareExchange(&g_childBusy, 0, 0) && g_childTick &&
            GetTickCount() - g_childTick > 30000 && g_share && g_share->magic == kMagic) {
            g_childTick = 0;
            g_share->error = 1006;
            InterlockedOr((volatile LONG*)&g_share->flags, 4);
            if (InterlockedCompareExchange(&g_share->state, 6, 1) == 1)
                InterlockedExchange(&g_childBusy, 0);   // 接管成功才放生，后续请求可继续派单
        }
        // st==8：正在扫描，空转等待（DirectStep 的扫描同步完成）
        Sleep(20);
    }

    SelfUnloadNoReturn();
    return 0;
}

// ---- 入口 ---------------------------------------------------------------------
// extern "C"：保证 -Wl,-e,DllMain 能精确命中（无 C++ 名修饰）。
// reserved 约定（手动映射加载时）：客户端在 explorer 里准备的"自裁桩"地址；
// 正常 LoadLibrary 动态加载时 reserved == NULL（回退 FreeLibraryAndExitThread）。
// 相位: 1=DllMain 2=已生成Worker 10=Worker入口 11=共享块OK 12=API解析完
//       13=hook装好 14=就绪主循环 20=DirectStep 21=静默扫描 22=直调执行 90=卸载
extern "C" BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = hModule;
        g_selfDestruct = (void(*)(void))reserved;
        InstallCrashBox();              // 最先装黑匣子（VEH + 共享页），再做事
        PHASE(1);
        InitializeCriticalSection(&g_cs);
        HANDLE dup = OpenMutexW(SYNCHRONIZE, FALSE, kMutexName);
        if (dup) { CloseHandle(dup); return TRUE; }   // 已驻留：第二次注入直接空转
        HANDLE t = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
        PHASE(2);
    } else if (reason == DLL_PROCESS_DETACH) {   // 手动映射时不会收到；防御性保留
        HookSWBRemove();
        HookIAMRemove();
    }
    return TRUE;
}
