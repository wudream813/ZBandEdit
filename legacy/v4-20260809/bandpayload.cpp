// ============================================================================
// bandpayload.cpp v4 —— 注入 explorer.exe 的载荷 DLL
//
//   模式1 (trampoline): inline hook user32!SetWindowBand，借 explorer 调用换参数
//   模式2 (direct)v4 : IAM key 双通道获取 —
//      【A 静默扫描】遍历 explorer 模块数据段/堆内存中的 8 字节候选值，逐个调用
//         user32#2510(NtUserEnableIAMAccess) 做"预言机验证"，命中即得 key。
//         —— 零按键、零焦点变化、不需要 explorer 做任何事情
//      【B 焦点诱导】扫描未命中时的兜底：焦点抖动到任务栏迫使 twinui 调 IAM，
//         hook 记录真实 key
//     拿到 key 后: EnableIAM(TRUE) → SetWindowBand → EnableIAM(FALSE) 同线程直调
//
// 编译:
//   cl /std:c++17 /LD /W4 /utf-8 bandpayload.cpp /link /OUT:bandedit-payload-x64.dll
//   g++ -std=c++17 -O2 -shared -o bandedit-payload-x64.dll bandpayload.cpp -static
//
// ⚠️ 仅限自己机器研究用途。
// ============================================================================
#include <windows.h>
#include <tlhelp32.h>

// 版本标识（客户端选文件时区分载荷版本）
extern "C" volatile const char kPayloadIdent[] = "BANDPAYLOAD_VER=4";

// ---- 与客户端共享的通信块 (Local\ZBandHookShareV1) ---------------------------
// state: 0=空闲 1=请求 2=成功 3=调用被拒 5=hook安装失败 6=direct失败 7=诱导捕获中 8=静默扫描中 9=卸载
// flags(payload→client): bit0 已捕获key bit1 无#2510 bit2 本次direct执行 bit3 key来自静默扫描
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
    DWORD              ver;       // payload 协议版本 = 4
    DWORD              mode;      // 0 = trampoline, 1 = direct
    DWORD              flags;
    DWORD              reserved[3];
};

static const wchar_t* kShareName = L"Local\\ZBandHookShareV1";
static const wchar_t* kMutexName = L"Local\\ZBandHookPayloadReadyV1";
static const DWORD    kMagic     = 0x444E425A;   // 'ZBND'
static const DWORD    kProtoVer  = 4;
static const DWORD    RF_SILENT  = 1;

static HMODULE     g_self   = nullptr;
static HANDLE      g_hMap   = nullptr;
static ShareBlock* g_share  = nullptr;
static HANDLE      g_ready  = nullptr;

// ---- 函数指针 ----------------------------------------------------------------
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
    SetLastError(0);
    BOOL ret = g_realSWB(h, a, b);
    DWORD err = ret ? 0 : GetLastError();
    HookSWBInstall();
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

// ---- v4【A 通道】静默内存扫描 + 预言机验证 ---------------------------------------
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
        if ((off & 0x3FFFF) == 0 && InterlockedCompareExchange(&g_scanAbort, 0, 0)) return false;
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
        bool twin = wcsstr(me.szModule, L"twinui") || wcsstr(me.szModule, L"TwinUI") ||
                    wcsstr(me.szModule, L"pcshell");
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

// 通道 A 主入口：模块 .data → twinui .data 已过 → 全进程私有 RW（带字节预算）
static bool AcquireKeyByScan() {
    if (!g_realIAM) return false;
    ULONG64 found = 0;
    InterlockedExchange(&g_scanAbort, 0);

    EnterCriticalSection(&g_cs);
    HookIAMRemove();                       // 整个扫描窗口内直调真实函数

    SIZE_T budget = 24ull * 1024 * 1024;   // 最多验证 ~2400 万个候选（防失控，~几秒）
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
                if (chunk > budget) chunk = budget;    // budget 以"候选数"折算太复杂，直接按字节减半封顶
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

// ---- v3 继承【B 通道】焦点诱导（兜底） -------------------------------------------
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
static void TryExecDirect() {
    if (!g_realIAM) {
        g_share->error  = 1001;
        g_share->result = 0;
        InterlockedOr((volatile LONG*)&g_share->flags, 2 | 4);
        InterlockedExchange(&g_share->state, 6);
        return;
    }
    // 1) 开通
    SetLastError(0);
    if (!CallRealIAM(g_iamKey, TRUE)) {
        g_share->result = 0;
        g_share->error  = g_callErr ? g_callErr : 1002;
        InterlockedOr((volatile LONG*)&g_share->flags, 4);
        InterlockedExchange(&g_share->state, 6);
        return;
    }
    // 2) 直调
    SetLastError(0);
    BOOL r = CallRealSWB((HWND)g_qHwnd, (HWND)g_qAfter, g_qBand);
    DWORD err = r ? 0 : g_callErr;
    CallRealIAM(g_iamKey, FALSE);

    g_share->result = (DWORD)r;
    g_share->error  = err;
    g_directPending = false;
    InterlockedOr((volatile LONG*)&g_share->flags, 4);
    InterlockedExchange(&g_share->state, r ? 2 : 3);
}

// direct 阶段推进：已key→执行；未key→先扫描，(非silent)再诱导
static bool g_scanTried = false;
static void DirectStep() {
    if (g_haveKey) { TryExecDirect(); return; }
    if (!g_scanTried) {
        g_scanTried = true;
        InterlockedExchange(&g_share->state, 8);          // 告诉客户端：静默扫描中
        if (AcquireKeyByScan()) { TryExecDirect(); return; }
        if (InterlockedCompareExchange(&g_share->state, 8, 8) == 0)  // 没被客户端取消
            InterlockedExchange(&g_share->state, 7);      // 回退到"诱导"阶段
        return;
    }
    if (g_reqSilent) {                                    // 严格静默：绝不碰焦点/输入
        g_share->error  = 1005;                           // 自定义: 扫描未命中且 --silent
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

// ---- 工作线程 -----------------------------------------------------------------
static DWORD WINAPI Worker(LPVOID) {
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

    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    g_realSWB = (PFN_SetWindowBand)(void*)GetProcAddress(u32, "SetWindowBand");
    g_realIAM = (PFN_EnableIAM)(void*)GetProcAddress(u32, MAKEINTRESOURCEA(2510));

    bool swbOk = g_realSWB && shareOk && HookSWBInstall();
    HookIAMInstall();

    if (shareOk) {
        InterlockedExchange((volatile LONG*)&g_share->ver, kProtoVer);
        if (!swbOk)     InterlockedExchange(&g_share->state, 5);
        if (!g_realIAM) InterlockedOr((volatile LONG*)&g_share->flags, 2);
    }
    g_ready = CreateMutexW(nullptr, FALSE, kMutexName);
    OutputDebugStringA((const char*)kPayloadIdent);
    if (!swbOk) return 0;

    for (;;) {
        LONG st = InterlockedCompareExchange(&g_share->state, 0, 0);
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
                DirectStep();
            } else if (!g_armed) {
                g_tHwnd  = (uintptr_t)g_share->hwnd;
                g_tAfter = (uintptr_t)g_share->insertAfter;
                g_tBand  = g_share->band;
                g_armed  = true;
            }
        } else if (st == 7) {
            if (g_directPending) DirectStep();
        } else if (st == 9) {
            break;
        }
        // st==8：正在扫描，空转等待（DirectStep 的扫描同步完成）
        Sleep(20);
    }

    EnterCriticalSection(&g_cs);
    HookSWBRemove();
    HookIAMRemove();
    LeaveCriticalSection(&g_cs);
    DeleteCriticalSection(&g_cs);
    if (g_share) UnmapViewOfFile(g_share);
    if (g_hMap)  CloseHandle(g_hMap);
    if (g_ready) CloseHandle(g_ready);
    FreeLibraryAndExitThread(g_self, 0);
    return 0;
}

// ---- 入口 ---------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        g_self = hModule;
        InitializeCriticalSection(&g_cs);
        HANDLE dup = OpenMutexW(SYNCHRONIZE, FALSE, kMutexName);
        if (dup) { CloseHandle(dup); return TRUE; }
        HANDLE t = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    } else if (reason == DLL_PROCESS_DETACH) {
        HookSWBRemove();
        HookIAMRemove();
    }
    return TRUE;
}
