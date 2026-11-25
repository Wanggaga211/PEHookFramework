// gui.cpp - PEHookGUI：PEHookFramework 可视化注入与 Hook 工具箱
//
// 功能：
//   1. 七种注入方式下拉选择（CreateRemoteThread / NtCreateThreadEx /
//      QueueUserAPC / RtlCreateUserThread / SetWindowsHookEx /
//      AppInit_DLLs / Reflective 远程反射注入）
//   2. 进程枚举（Toolhelp32），双击列表项自动填入 PID
//   3. DLL 路径选择（文件对话框）+ 手工输入
//   4. 一键注入（后台线程执行，不卡界面），AppInit 停用
//   5. 本机五模块自测（反射加载 / IAT Hook / Inline Hook / VT Hook / Context Hook）
//   6. 运行日志：界面日志区（Unicode）+ 控制台（UTF-8 代码页）双通道
//
// 注：注入/Hook 需要管理员权限（vcxproj 已嵌入 requireAdministrator 清单）。
//     界面全部走 W 系列 API（UTF-16），中文显示不受 ANSI 代码页影响。
#include "common.h"
#include "inject.h"
#include "reflective.h"
#include "iathook.h"
#include "inlinehook.h"
#include "vthook.h"
#include "contexthook.h"

#include <tlhelp32.h>
#include <commdlg.h>
#include <process.h>

// 启用 Windows 视觉样式（Common Controls v6）
#pragma comment(linker, "\"/manifestdependency:processorArchitecture='*' type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' language='*' publicKeyToken='6595b64144ccf1df'\"")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")

// ---------- 控件 ID ----------
#define IDC_COMBO_METHOD   1001
#define IDC_EDIT_PID       1002
#define IDC_EDIT_DLL       1003
#define IDC_LIST_PROC      1004
#define IDC_BTN_REFRESH    1005
#define IDC_BTN_BROWSE     1006
#define IDC_BTN_INJECT     1007
#define IDC_BTN_APPINIT_OFF 1008
#define IDC_BTN_SELFTEST   1009
#define IDC_BTN_CLEAR      1010
#define IDC_EDIT_LOG       1011
#define IDC_LBL_STATUS     1012

// 自定义消息（后台线程 -> 主窗口）
#define WM_APP_INJECT_DONE    (WM_APP + 1)
#define WM_APP_SELFTEST_DONE  (WM_APP + 2)

// ---------- 全局句柄 ----------
static HWND g_hWnd = NULL;
static HWND g_hComboMethod = NULL;
static HWND g_hEditPid = NULL;
static HWND g_hEditDll = NULL;
static HWND g_hListProc = NULL;
static HWND g_hEditLog = NULL;
static HWND g_hLblStatus = NULL;
static HFONT g_hFont = NULL;

// 注入线程参数
struct InjectArgs {
    int    method;
    DWORD  pid;
    char   dll[MAX_PATH];   // GBK(CP_ACP) 编码，供 ANSI 注入 API 直接使用
};

// ---------- 日志：界面日志区(Unicode) + 控制台(UTF-8) ----------
void GuiLog(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (g_hEditLog) {
        wchar_t wbuf[1200];
        MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, 1200);
        wchar_t line[1300];
        _snwprintf_s(line, _TRUNCATE, L"%s\r\n", wbuf);
        int len = GetWindowTextLengthW(g_hEditLog);
        SendMessageW(g_hEditLog, EM_SETSEL, len, len);
        SendMessageW(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)line);
        SendMessageW(g_hEditLog, EM_SCROLLCARET, 0, 0);
    }
    printf("%s\n", buf);          // 控制台为 CP_UTF8，UTF-8 字节直接正确显示
    OutputDebugStringA(buf);
}

// 窄字符串(ASCII/UTF-8) 转宽，用于给 Unicode 控件发消息
static void ComboAddString(HWND h, const char* s)
{
    wchar_t w[128];
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, 128);
    SendMessageW(h, CB_ADDSTRING, 0, (LPARAM)w);
}

// ---------- 进程枚举 ----------
void RefreshProcessList()
{
    SendMessageW(g_hListProc, LB_RESETCONTENT, 0, 0);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            wchar_t line[300];
            _snwprintf_s(line, _TRUNCATE, L"%lu  %s", pe.th32ProcessID, pe.szExeFile);
            int idx = (int)SendMessageW(g_hListProc, LB_ADDSTRING, 0, (LPARAM)line);
            SendMessageW(g_hListProc, LB_SETITEMDATA, idx, (LPARAM)pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    GuiLog("[进程] 已刷新进程列表，共 %d 个进程",
        (int)SendMessageW(g_hListProc, LB_GETCOUNT, 0, 0));
}

// ---------- DLL 浏览 ----------
void BrowseDll()
{
    wchar_t path[MAX_PATH] = { 0 };
    OPENFILENAMEW ofn = { sizeof(ofn) };
    ofn.hwndOwner = g_hWnd;
    ofn.lpstrFilter = L"DLL 文件 (*.dll)\0*.dll\0所有文件 (*.*)\0*.*\0\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = L"选择要注入的 DLL";
    if (GetOpenFileNameW(&ofn))
        SetWindowTextW(g_hEditDll, path);
}

// 从 DLL 输入框取路径：返回宽字符串；调用方按需转 GBK 传给注入 API
static void GetDllPathW(wchar_t* out, int cap)
{
    GetWindowTextW(g_hEditDll, out, cap);
}

// ---------- 注入执行（后台线程） ----------
unsigned __stdcall InjectThread(void* p)
{
    InjectArgs* a = (InjectArgs*)p;
    int method = a->method;
    DWORD pid = a->pid;
    char dll[MAX_PATH];
    memcpy(dll, a->dll, MAX_PATH);
    free(a);

    GuiLog("[注入] 开始：方式=%s PID=%lu DLL=%s",
        InjectMethodName((InjectMethod)method), pid, dll);
    bool ok = InjectIntoProcess((InjectMethod)method, pid, dll);
    GuiLog("[注入] %s", ok ? "成功" : "失败（查看控制台详细日志）");
    PostMessageW(g_hWnd, WM_APP_INJECT_DONE, ok ? 1 : 0, method);
    return 0;
}

void StartInject()
{
    int method = (int)SendMessageW(g_hComboMethod, CB_GETCURSEL, 0, 0);
    if (method == CB_ERR) {
        GuiLog("[注入] 请先选择注入方式");
        return;
    }
    wchar_t pidText[64] = { 0 };
    GetWindowTextW(g_hEditPid, pidText, 64);
    DWORD pid = (DWORD)_wtoi(pidText);
    if (pid == 0) {
        GuiLog("[注入] 请填写有效的目标 PID");
        return;
    }
    wchar_t dllW[MAX_PATH] = { 0 };
    GetWindowTextW(g_hEditDll, dllW, MAX_PATH);
    if (dllW[0] == 0) {
        GuiLog("[注入] 请填写 DLL 路径");
        return;
    }
    // 反射注入提示：引导模块 PEHookLoaderStub.dll 需与目标 DLL 同目录
    if (method == INJECT_REFLECTIVE)
        GuiLog("[注入] 反射注入要求 PEHookLoaderStub.dll 与所选 DLL 位于同一目录");

    InjectArgs* a = (InjectArgs*)malloc(sizeof(InjectArgs));
    if (!a) return;
    a->method = method;
    a->pid = pid;
    // 宽路径 -> GBK(CP_ACP)，与 inject.cpp 内部 ANSI API 保持一致
    WideCharToMultiByte(CP_ACP, 0, dllW, -1, a->dll, MAX_PATH, NULL, NULL);

    EnableWindow(GetDlgItem(g_hWnd, IDC_BTN_INJECT), FALSE);
    _beginthreadex(NULL, 0, InjectThread, a, 0, NULL);
}

// ---------- 自测（后台线程） ----------
static int g_origMsgBox = 0;
static void* g_origGetValue = NULL;

static int WINAPI FakeMsgBox(HWND, LPCSTR text, LPCSTR caption, UINT)
{
    GuiLog("[IAT-Fake] MessageBoxA 被劫持: %s | %s", caption ? caption : "", text ? text : "");
    return IDOK;
}

static void WINAPI FakeHookTarget(int* out)
{
    GuiLog("[Inline-Fake] Demo_HookTarget 被劫持 (入参 *out=%d)", *out);
    *out = 0x22;
}

static int FakeGetValue(void* self)
{
    GuiLog("[VT-Fake] CConfig::GetValue 被劫持");
    (void)self;
    return 0xDEAD;
}

static volatile LONG g_workerCount = 0;
static volatile BOOL g_workerRunning = TRUE;

static DWORD WINAPI WorkerThread(LPVOID)
{
    GuiLog("[Context] WorkerThread 启动 (TID=%lu)", GetCurrentThreadId());
    while (g_workerRunning) {
        InterlockedIncrement(&g_workerCount);
        Sleep(100);
    }
    return 0;
}

static DWORD WINAPI FakeWorker(LPVOID)
{
    GuiLog("[Context-Fake] 线程已重定向到 FakeWorker (TID=%lu)", GetCurrentThreadId());
    g_workerRunning = FALSE;
    Sleep(1000);
    return 0;
}

static HMODULE ReflectiveLoadWrapper(const char* dllPath)
{
    __try {
        return LoadLibraryFromMemoryFile(dllPath);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

bool RunSelfDemoAll()
{
    char demoPath[MAX_PATH];
    GetModuleFileNameA(NULL, demoPath, MAX_PATH);
    char* slash = strrchr(demoPath, '\\');
    if (slash)
        strcpy_s(slash + 1, MAX_PATH - (slash + 1 - demoPath), "PEHookDemo.dll");
    else
        strcpy_s(demoPath, "PEHookDemo.dll");

    bool all = true;

    // 1/5 反射加载
    GuiLog("== 1/5 反射式DLL加载 ==");
    HMODULE hDemo = ReflectiveLoadWrapper(demoPath);
    if (!hDemo) {
        GuiLog("[失败] 反射加载 %s 失败", demoPath);
        return false;
    }
    typedef int(WINAPI* Add_t)(int, int);
    Add_t pAdd = (Add_t)FindExport(hDemo, "Demo_Add");
    int r = pAdd(30, 12);
    bool ok1 = (r == 42);
    GuiLog("反射加载成功: 模块=%p, Demo_Add(30,12)=%d (期望 42)", (void*)hDemo, r);
    all &= ok1;

    // 2/5 IAT Hook
    GuiLog("== 2/5 IAT Hook ==");
    bool ok2 = IATHook_ReplaceInModule(hDemo, "MessageBoxA", (void*)FakeMsgBox, (void**)&g_origMsgBox);
    if (ok2) {
        typedef int(WINAPI* CallMsg_t)(void);
        CallMsg_t pCall = (CallMsg_t)FindExport(hDemo, "Demo_CallMessageBox");
        int r2 = pCall();
        ok2 = (r2 == IDOK);
        GuiLog("IAT Hook 生效: Demo_CallMessageBox 返回 %d", r2);
    }
    all &= ok2;

    // 3/5 Inline Hook（Hde + 蹦床 + 还原）
    GuiLog("== 3/5 Inline Hook (Hde32/64 + 蹦床) ==");
    typedef void(WINAPI* Target_t)(int*);
    Target_t pTarget = (Target_t)FindExport(hDemo, "Demo_HookTarget");
    int v = 1;
    pTarget(&v);
    GuiLog("Hook 前 Demo_HookTarget(1) -> %#x (期望 0x1012)", v);
    void* tramp = NULL;
    bool ok3 = pTarget && InlineHook_Install((void*)pTarget, (void*)FakeHookTarget, &tramp);
    if (ok3) {
        v = 1;
        pTarget(&v);
        ok3 = (v == 0x22);
        GuiLog("Hook 后 Demo_HookTarget(1) -> %#x (期望 0x22)", v);
        if (tramp) {
            int t2 = 1;
            ((Target_t)tramp)(&t2);
            GuiLog("蹦床调用原函数 -> %#x (期望 0x1012)", t2);
            ok3 = ok3 && (t2 == 0x1012);
        }
        InlineHook_Uninstall((void*)pTarget, (void*)FakeHookTarget, tramp);
    }
    all &= ok3;

    // 4/5 VT Hook
    GuiLog("== 4/5 VT Hook ==");
    typedef void* (WINAPI* Create_t)(void);
    typedef int(WINAPI* Get_t)(void*);
    Create_t pCreate = (Create_t)FindExport(hDemo, "CreateConfig");
    Get_t pGet = (Get_t)FindExport(hDemo, "Config_GetValue");
    bool ok4 = false;
    if (pCreate && pGet) {
        void* cfg = pCreate();
        int before = pGet(cfg);
        GuiLog("Hook 前 GetValue = %d (期望 7)", before);
        if (VTHook_Replace(cfg, 0, (void*)FakeGetValue, &g_origGetValue)) {
            int after = pGet(cfg);
            ok4 = (after == 0xDEAD);
            GuiLog("Hook 后 GetValue = %#x (期望 0xDEAD)", after);
        }
    }
    all &= ok4;

    // 5/5 Context Hook
    GuiLog("== 5/5 Context Hook (EIP/RIP 线程上下文) ==");
    HANDLE hThread = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    bool ok5 = false;
    if (hThread) {
        Sleep(400);
        LONG before = g_workerCount;
        CONTEXT saved;
        memset(&saved, 0, sizeof(saved));
        if (ContextHook_Redirect(hThread, (void*)FakeWorker, &saved)) {
            Sleep(400);
            LONG after = g_workerCount;
            ok5 = (after == before);
            GuiLog("重定向后计数=%ld (Hook 生效: %s)", after, ok5 ? "是" : "否");
            ContextHook_Restore(hThread, &saved);
        }
        CloseHandle(hThread);
    }
    all &= ok5;

    GuiLog("======== 自测结果: %s ========", all ? "全部通过" : "存在失败项");
    return all;
}

unsigned __stdcall SelfTestThread(void*)
{
    bool ok = RunSelfDemoAll();
    PostMessageW(g_hWnd, WM_APP_SELFTEST_DONE, ok ? 1 : 0, 0);
    return 0;
}

// ---------- 控件创建 ----------
void AddChild(HWND parent, HWND* ph, LPCWSTR cls, LPCWSTR text, int id,
              int x, int y, int w, int hh, DWORD style)
{
    HWND hw = CreateWindowExW(0, cls, text, style | WS_CHILD | WS_VISIBLE,
                              x, y, w, hh, parent, (HMENU)(INT_PTR)id,
                              GetModuleHandleW(NULL), NULL);
    if (hw && g_hFont)
        SendMessageW(hw, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    if (ph) *ph = hw;
}

// ---------- 主窗口 ----------
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        g_hWnd = hWnd;
        g_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        // 注入设置组
        HWND hGrp = CreateWindowExW(0, L"BUTTON", L"注入设置",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 10, 8, 540, 120,
            hWnd, NULL, GetModuleHandleW(NULL), NULL);
        if (g_hFont) SendMessageW(hGrp, WM_SETFONT, (WPARAM)g_hFont, TRUE);

        AddChild(hWnd, NULL, L"STATIC", L"注入方式:", 0, 20, 32, 70, 20, SS_LEFT);
        AddChild(hWnd, &g_hComboMethod, L"COMBOBOX", L"",
            IDC_COMBO_METHOD, 92, 30, 190, 260,
            CBS_DROPDOWNLIST | WS_VSCROLL);
        for (int i = 0; i < INJECT_METHOD_COUNT; i++)
            ComboAddString(g_hComboMethod, InjectMethodName((InjectMethod)i));
        SendMessageW(g_hComboMethod, CB_SETCURSEL, 0, 0);

        AddChild(hWnd, NULL, L"STATIC", L"PID:", 0, 300, 32, 40, 20, SS_LEFT);
        AddChild(hWnd, &g_hEditPid, L"EDIT", L"", IDC_EDIT_PID, 340, 30, 70, 22, ES_NUMBER | WS_BORDER);
        AddChild(hWnd, NULL, L"BUTTON", L"刷新进程", IDC_BTN_REFRESH, 420, 30, 110, 26, BS_PUSHBUTTON);

        AddChild(hWnd, NULL, L"STATIC", L"DLL 路径:", 0, 20, 66, 70, 20, SS_LEFT);
        AddChild(hWnd, &g_hEditDll, L"EDIT", L"", IDC_EDIT_DLL, 92, 64, 350, 22, ES_AUTOHSCROLL | WS_BORDER);
        AddChild(hWnd, NULL, L"BUTTON", L"浏览...", IDC_BTN_BROWSE, 450, 64, 80, 26, BS_PUSHBUTTON);

        AddChild(hWnd, NULL, L"BUTTON", L"执行注入", IDC_BTN_INJECT, 20, 100, 120, 26, BS_PUSHBUTTON);
        AddChild(hWnd, NULL, L"BUTTON", L"停用 AppInit", IDC_BTN_APPINIT_OFF, 150, 100, 110, 26, BS_PUSHBUTTON);
        AddChild(hWnd, NULL, L"BUTTON", L"本机自测(5项)", IDC_BTN_SELFTEST, 270, 100, 130, 26, BS_PUSHBUTTON);
        AddChild(hWnd, NULL, L"BUTTON", L"清空日志", IDC_BTN_CLEAR, 410, 100, 110, 26, BS_PUSHBUTTON);

        // 进程列表组
        HWND hGrp2 = CreateWindowExW(0, L"BUTTON", L"进程列表（双击填入 PID）",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 10, 136, 540, 150,
            hWnd, NULL, GetModuleHandleW(NULL), NULL);
        if (g_hFont) SendMessageW(hGrp2, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        AddChild(hWnd, &g_hListProc, L"LISTBOX", L"", IDC_LIST_PROC,
            20, 156, 520, 122, LBS_NOTIFY | WS_VSCROLL | WS_BORDER);

        // 日志组
        HWND hGrp3 = CreateWindowExW(0, L"BUTTON", L"运行日志（详细输出见控制台窗口）",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 10, 294, 540, 190,
            hWnd, NULL, GetModuleHandleW(NULL), NULL);
        if (g_hFont) SendMessageW(hGrp3, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        AddChild(hWnd, &g_hEditLog, L"EDIT", L"", IDC_EDIT_LOG,
            20, 314, 520, 162,
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_BORDER);

        // 状态栏
        AddChild(hWnd, &g_hLblStatus, L"STATIC", L"就绪",
            IDC_LBL_STATUS, 10, 490, 540, 20, SS_LEFT);

        RefreshProcessList();
        GuiLog("PEHookGUI 就绪 - 架构: %s", sizeof(void*) == 8 ? "x64" : "x86");
        GuiLog("提示：注入/Hook 需要以管理员身份运行本程序");
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        switch (id) {
        case IDC_BTN_REFRESH:
            RefreshProcessList();
            break;
        case IDC_BTN_BROWSE:
            BrowseDll();
            break;
        case IDC_BTN_INJECT:
            StartInject();
            break;
        case IDC_BTN_APPINIT_OFF: {
            wchar_t dllW[MAX_PATH] = { 0 };
            GetDllPathW(dllW, MAX_PATH);
            if (dllW[0] == 0) {
                GuiLog("[AppInit] 请先填写 DLL 路径");
                break;
            }
            char dll[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, dllW, -1, dll, MAX_PATH, NULL, NULL);
            bool ok = InjectViaAppInitDlls(dll, false);
            GuiLog("[AppInit] 停用 %s", ok ? "成功" : "失败");
            SetWindowTextW(g_hLblStatus, ok ? L"AppInit 已停用" : L"AppInit 停用失败");
            break;
        }
        case IDC_BTN_SELFTEST:
            EnableWindow(GetDlgItem(hWnd, IDC_BTN_SELFTEST), FALSE);
            GuiLog("== 开始本机五模块自测 ==");
            _beginthreadex(NULL, 0, SelfTestThread, NULL, 0, NULL);
            break;
        case IDC_BTN_CLEAR:
            SetWindowTextW(g_hEditLog, L"");
            break;
        case IDC_LIST_PROC:
            if (HIWORD(wParam) == LBN_DBLCLK) {
                int idx = (int)SendMessageW(g_hListProc, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    DWORD pid = (DWORD)SendMessageW(g_hListProc, LB_GETITEMDATA, idx, 0);
                    wchar_t buf[32];
                    _snwprintf_s(buf, _TRUNCATE, L"%lu", pid);
                    SetWindowTextW(g_hEditPid, buf);
                    GuiLog("[进程] 已填入 PID=%lu", pid);
                }
            }
            break;
        }
        return 0;
    }

    case WM_APP_INJECT_DONE: {
        bool ok = (wParam == 1);
        SetWindowTextW(g_hLblStatus, ok ? L"注入完成（成功）" : L"注入失败（见日志/控制台）");
        EnableWindow(GetDlgItem(hWnd, IDC_BTN_INJECT), TRUE);
        GuiLog("[注入] 线程结束，结果: %s", ok ? "成功" : "失败");
        break;
    }

    case WM_APP_SELFTEST_DONE: {
        bool ok = (wParam == 1);
        EnableWindow(GetDlgItem(hWnd, IDC_BTN_SELFTEST), TRUE);
        SetWindowTextW(g_hLblStatus, ok ? L"自测：全部通过" : L"自测：存在失败项");
        MessageBoxW(hWnd, ok ? L"五模块自测全部通过！" : L"自测存在失败项，详见日志。",
                    L"PEHookGUI 自测", MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONERROR));
        break;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow)
{
    // 附一个控制台窗口承载共享源码的 printf 详细日志；
    // 控制台输出代码页设为 UTF-8，与源码 /utf-8 字面量一致，中文不乱码。
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
    wc.lpszClassName = L"PEHookGUIWindow";
    RegisterClassExW(&wc);

    RECT rc = { 0, 0, 560, 520 };
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);
    HWND hWnd = CreateWindowExW(0, wc.lpszClassName, L"PEHookFramework - 注入与 Hook 工具箱",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        NULL, NULL, hInstance, NULL);
    if (!hWnd) {
        MessageBoxW(NULL, L"主窗口创建失败", L"PEHookGUI", MB_OK | MB_ICONERROR);
        return 1;
    }

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
