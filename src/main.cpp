// main.cpp - PEHookInjector.exe：CLI 入口 + 本进程全功能自测
//
// 用法：
//   PEHookInjector.exe selfdemo
//       在本进程内演示：反射加载 + IAT Hook + Inline Hook + VT Hook + Context Hook
//   PEHookInjector.exe inject --method <名> --pid <进程ID> --dll <DLL路径>
//       注入方式名: CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|
//                   RtlCreateUserThread|SetWindowsHookEx|AppInit_DLLs|Reflective
//   PEHookInjector.exe appinit --enable|--disable --dll <DLL路径>
//   PEHookInjector.exe help
#include "common.h"
#include "reflective.h"
#include "inject.h"
#include "iathook.h"
#include "inlinehook.h"
#include "vthook.h"
#include "contexthook.h"

#include <process.h>

// ================= 自测用全局 =================
static int g_origMsgBox = 0;
static void* g_origGetValue = NULL;

// ---- IAT Hook 的 Fake：替换 MessageBoxA ----
static int WINAPI FakeMsgBox(HWND hWnd, LPCSTR text, LPCSTR caption, UINT type)
{
    LOG("[IAT-Fake] MessageBoxA 被劫持: %s | %s", caption ? caption : "", text ? text : "");
    return IDOK;
}

// ---- Inline Hook 的 Detour：替换 Demo_HookTarget ----
static void WINAPI FakeHookTarget(int* out)
{
    LOG("[Inline-Fake] Demo_HookTarget 被劫持 (入参 *out=%d)", *out);
    *out = 0x22;
}

// ---- VT Hook 的 Fake：替换 CConfig::GetValue ----
static int FakeGetValue(void* self)
{
    LOG("[VT-Fake] CConfig::GetValue 被劫持");
    (void)self;
    return 0xDEAD;
}

// ---- Context Hook 演示线程 ----
static volatile LONG g_workerCount = 0;
static volatile BOOL g_workerRunning = TRUE;

static DWORD WINAPI WorkerThread(LPVOID)
{
    LOG("WorkerThread 启动 (TID=%lu)", GetCurrentThreadId());
    while (g_workerRunning) {
        InterlockedIncrement(&g_workerCount);
        Sleep(100);
    }
    return 0;
}

static DWORD WINAPI FakeWorker(LPVOID)
{
    LOG("[Context-Fake] 线程已重定向到 FakeWorker (TID=%lu)", GetCurrentThreadId());
    g_workerRunning = FALSE; // 停掉原循环计数，便于观察
    Sleep(5000);
    return 0;
}

// ================= 反射加载自测 =================
// SEH 捕获：定位反射加载内部崩溃的指令地址
static HMODULE g_sehDemo = NULL;
static DWORD g_sehCode = 0;
static ULONG_PTR g_sehRip = 0;

static HMODULE ReflectiveLoadWrapper(const char* dllPath)
{
    __try {
        return LoadLibraryFromMemoryFile(dllPath);
    } __except (g_sehCode = GetExceptionCode(),
                g_sehRip = (ULONG_PTR)((EXCEPTION_RECORD*)GetExceptionInformation())->ExceptionAddress,
                EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

static bool SelfTestReflective(const char* demoDllPath)
{
    LOG("== 1/5 反射式DLL加载 ==");
    g_sehDemo = ReflectiveLoadWrapper(demoDllPath);
    if (!g_sehDemo) {
        LOG_ERR("反射加载失败 (SEH: code=0x%X rip=%p): %s", g_sehCode, (void*)g_sehRip, demoDllPath);
        return false;
    }
    typedef int(WINAPI* Add_t)(int, int);
    Add_t pAdd = (Add_t)FindExport(g_sehDemo, "Demo_Add");
    if (!pAdd) {
        LOG_ERR("FindExport(Demo_Add) 失败");
        return false;
    }
    int r = pAdd(30, 12);
    LOG("反射加载成功: 模块=%p, Demo_Add(30,12)=%d (期望 42)", (void*)g_sehDemo, r);
    return r == 42;
}

// ================= IAT Hook 自测 =================
static bool SelfTestIat(HMODULE hDemo)
{
    LOG("== 2/5 IAT Hook ==");
    if (!IATHook_ReplaceInModule(hDemo, "MessageBoxA", (void*)FakeMsgBox, (void**)&g_origMsgBox)) {
        LOG_ERR("IAT Hook 安装失败");
        return false;
    }
    typedef int(WINAPI* CallMsg_t)(void);
    CallMsg_t pCall = (CallMsg_t)FindExport(hDemo, "Demo_CallMessageBox");
    int r = pCall();
    bool ok = (r == IDOK);
    LOG("IAT Hook 生效: Demo_CallMessageBox 返回 %d, 原始地址=%p", r, g_origMsgBox);
    return ok;
}

// ================= Inline Hook 自测 =================
static bool SelfTestInline(HMODULE hDemo)
{
    LOG("== 3/5 Inline Hook (Hde32/64 + 蹦床) ==");
    typedef void(WINAPI* Target_t)(int*);
    Target_t pTarget = (Target_t)FindExport(hDemo, "Demo_HookTarget");
    if (!pTarget)
        return false;

    int v = 1;
    pTarget(&v);
    LOG("Hook 前 Demo_HookTarget(1) -> %#x (期望 0x1012)", v);

    void* tramp = NULL;
    if (!InlineHook_Install((void*)pTarget, (void*)FakeHookTarget, &tramp))
        return false;

    v = 1;
    pTarget(&v);
    bool hooked = (v == 0x22);
    LOG("Hook 后 Demo_HookTarget(1) -> %#x (期望 0x22)", v);

    // 蹦床：调用原逻辑
    if (tramp) {
        int t2 = 1;
        ((Target_t)tramp)(&t2);
        LOG("蹦床调用原函数 -> %#x (期望 0x1012)", t2);
        hooked = hooked && (t2 == 0x1012);
    }

    // 还原
    InlineHook_Uninstall((void*)pTarget, (void*)FakeHookTarget, tramp);
    v = 1;
    pTarget(&v);
    LOG("还原后 Demo_HookTarget(1) -> %#x (期望 0x1012)", v);
    return hooked;
}

// ================= VT Hook 自测 =================
static bool SelfTestVt(HMODULE hDemo)
{
    LOG("== 4/5 VT Hook ==");
    typedef void* (WINAPI* Create_t)(void);
    typedef int(WINAPI* Get_t)(void*);
    Create_t pCreate = (Create_t)FindExport(hDemo, "CreateConfig");
    Get_t pGet = (Get_t)FindExport(hDemo, "Config_GetValue");
    if (!pCreate || !pGet)
        return false;

    void* cfg = pCreate();
    int before = pGet(cfg);
    LOG("Hook 前 GetValue = %d (期望 7)", before);

    if (!VTHook_Replace(cfg, 0, (void*)FakeGetValue, &g_origGetValue))
        return false;

    int after = pGet(cfg);
    bool ok = (after == 0xDEAD);
    LOG("Hook 后 GetValue = %#x (期望 0xDEAD), 原槽位=%p", after, g_origGetValue);
    return ok;
}

// ================= Context Hook 自测 =================
static bool SelfTestContext()
{
    LOG("== 5/5 Context Hook (EIP/RIP 线程上下文注入) ==");
    HANDLE hThread = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    if (!hThread)
        return false;
    Sleep(500);
    LONG before = g_workerCount;
    LOG("WorkerThread 运行中, 计数=%ld", before);

    CONTEXT saved;
    memset(&saved, 0, sizeof(saved));
    if (!ContextHook_Redirect(hThread, (void*)FakeWorker, &saved)) {
        CloseHandle(hThread);
        return false;
    }
    Sleep(400);
    LONG after = g_workerCount;
    bool ok = (after == before); // 计数停止增长 => 线程已不在 WorkerThread
    LOG("重定向后计数=%ld (Hook 生效: %s)", after, ok ? "是" : "否");

    // 演示结束恢复原上下文
    ContextHook_Restore(hThread, &saved);
    CloseHandle(hThread);
    return ok;
}

// ================= 自测主流程 =================
static int RunSelfDemo()
{
    // exe 同目录下的 demo DLL
    char demoPath[MAX_PATH];
    GetModuleFileNameA(NULL, demoPath, MAX_PATH);
    char* slash = strrchr(demoPath, '\\');
    if (slash)
        strcpy_s(slash + 1, MAX_PATH - (slash + 1 - demoPath), "PEHookDemo.dll");
    else
        strcpy_s(demoPath, "PEHookDemo.dll");

#ifdef _WIN64
    LOG("======== PEHookFramework 自测开始 (架构: x64) ========");
#else
    LOG("======== PEHookFramework 自测开始 (架构: x86) ========");
#endif
    bool all = true;
    all &= SelfTestReflective(demoPath);   // 反射加载，得到 hDemo（全局 g_sehDemo）

    HMODULE hDemo = g_sehDemo;
    if (!hDemo) {
        all = false;
    } else {
        all &= SelfTestIat(hDemo);
        all &= SelfTestInline(hDemo);
        all &= SelfTestVt(hDemo);
    }
    all &= SelfTestContext();

    LOG("======== 自测结果: %s ========", all ? "全部通过" : "存在失败项");
    return all ? 0 : 1;
}

// ================= CLI 注入 =================
static void PrintUsage()
{
    printf(
        "PEHookInjector - Ring3 PE Hook 与注入框架\n"
        "用法:\n"
        "  PEHookInjector.exe selfdemo\n"
        "  PEHookInjector.exe inject --method <注入方式> --pid <PID> --dll <DLL路径>\n"
        "  PEHookInjector.exe appinit --enable|--disable --dll <DLL路径>\n"
        "注入方式: CreateRemoteThread | NtCreateThreadEx | QueueUserAPC |\n"
        "          RtlCreateUserThread | SetWindowsHookEx | AppInit_DLLs | Reflective\n"
        "示例:\n"
        "  PEHookInjector.exe inject --method CreateRemoteThread --pid 1234 --dll C:\\demo\\PEHookDemo.dll\n");
}

static int RunInject(int argc, char* argv[])
{
    const char* method = NULL;
    const char* dll = NULL;
    DWORD pid = 0;
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--method") == 0 && i + 1 < argc)
            method = argv[++i];
        else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            pid = (DWORD)atoi(argv[++i]);
        else if (strcmp(argv[i], "--dll") == 0 && i + 1 < argc)
            dll = argv[++i];
    }
    if (!method || !dll || pid == 0) {
        PrintUsage();
        return 2;
    }

    InjectMethod m;
    if (_stricmp(method, "CreateRemoteThread") == 0)      m = INJECT_CREATE_REMOTE_THREAD;
    else if (_stricmp(method, "NtCreateThreadEx") == 0)   m = INJECT_NT_CREATE_THREAD_EX;
    else if (_stricmp(method, "QueueUserAPC") == 0)       m = INJECT_QUEUE_USER_APC;
    else if (_stricmp(method, "RtlCreateUserThread") == 0) m = INJECT_RTL_CREATE_USER_THREAD;
    else if (_stricmp(method, "SetWindowsHookEx") == 0)   m = INJECT_SET_WINDOWS_HOOK_EX;
    else if (_stricmp(method, "AppInit_DLLs") == 0)       m = INJECT_APPINIT_DLLS;
    else if (_stricmp(method, "Reflective") == 0)         m = INJECT_REFLECTIVE;
    else {
        printf("未知注入方式: %s\n", method);
        PrintUsage();
        return 2;
    }

    LOG("开始注入: 方式=%s, PID=%lu, DLL=%s", InjectMethodName(m), pid, dll);
    return InjectIntoProcess(m, pid, dll) ? 0 : 1;
}

static int RunAppInit(int argc, char* argv[])
{
    const char* dll = NULL;
    bool enable = false;
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--enable") == 0)
            enable = true;
        else if (strcmp(argv[i], "--disable") == 0)
            enable = false;
        else if (strcmp(argv[i], "--dll") == 0 && i + 1 < argc)
            dll = argv[++i];
    }
    if (!dll) {
        PrintUsage();
        return 2;
    }
    return InjectViaAppInitDlls(dll, enable) ? 0 : 1;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        PrintUsage();
        return 2;
    }
    if (strcmp(argv[1], "selfdemo") == 0)
        return RunSelfDemo();
    if (strcmp(argv[1], "inject") == 0)
        return RunInject(argc, argv);
    if (strcmp(argv[1], "appinit") == 0)
        return RunAppInit(argc, argv);
    PrintUsage();
    return 2;
}
