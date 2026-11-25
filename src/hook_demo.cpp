// hook_demo.cpp - PEHookDemo.dll：四种 Hook 与注入的演示目标
//   * Demo_Add / Demo_HookTarget      -> Inline Hook 演示目标
//   * Demo_CallMessageBox             -> IAT Hook 演示目标（内部调用 MessageBoxA）
//   * CreateConfig + CConfig          -> VT Hook 演示目标
//   * HookProc                        -> SetWindowsHookEx 注入演示回调
// 运行日志写入 %TEMP%\PEHookDemo.log
#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>

namespace {

FILE* OpenLog()
{
    static char path[MAX_PATH] = { 0 };
    if (!path[0]) {
        GetTempPathA(MAX_PATH, path);
        strcat_s(path, "PEHookDemo.log");
    }
    FILE* f = NULL;
    fopen_s(&f, path, "a");
    return f;
}

void WriteLog(const char* fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    OutputDebugStringA(buf);
    FILE* f = OpenLog();
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%02u:%02u:%02u.%03u] %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
        fclose(f);
    }
}

// VT Hook 演示类：GetValue 在 vtable 槽 0，SetValue 在槽 1
class CConfig {
public:
    virtual int GetValue() { return m_value; }
    virtual void SetValue(int v) { m_value = v; }
private:
    int m_value = 7;
};

} // namespace

extern "C" {

// 供外部调用的日志接口
__declspec(dllexport) void WINAPI LogLine(const char* msg)
{
    WriteLog("%s", msg ? msg : "");
}

// ---- Inline Hook 目标：函数体足够长（>= 12 字节 x64），头部无相对跳转 ----
__declspec(dllexport) int WINAPI Demo_Add(int a, int b)
{
    WriteLog("Demo_Add(%d, %d) 被调用 -> %d", a, b, a + b);
    return a + b;
}

__declspec(dllexport) void WINAPI Demo_HookTarget(int* out)
{
    int t = 0x11;
    t += *out;
    *out = t | 0x1000;
}

// ---- IAT Hook 目标：内部调用 MessageBoxA ----
__declspec(dllexport) int WINAPI Demo_CallMessageBox(void)
{
    WriteLog("Demo_CallMessageBox: 即将调用 MessageBoxA");
    int r = MessageBoxA(NULL, "这是 PEHookDemo 的原始 MessageBoxA", "PEHookDemo", MB_OK);
    WriteLog("Demo_CallMessageBox: MessageBoxA 返回 %d", r);
    return r;
}

// ---- VT Hook 目标 ----
__declspec(dllexport) void* WINAPI CreateConfig(void)
{
    CConfig* c = new CConfig();
    WriteLog("CreateConfig: 新对象 %p, GetValue 槽初始值 = %d", (void*)c, c->GetValue());
    return c;
}

// 供 VT Hook 验证：调用虚函数
__declspec(dllexport) int WINAPI Config_GetValue(void* pObj)
{
    return ((CConfig*)pObj)->GetValue();
}

// ---- SetWindowsHookEx 注入演示回调（必须在本 DLL 内） ----
__declspec(dllexport) LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    WriteLog("HookProc(nCode=%d) 注入回调生效", nCode);
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

} // extern "C"

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    (void)hInst;
    // 注意：反射加载的 DLL 不在进程模块表，DllMain 内禁止调用
    // DisableThreadLibraryCalls / GetModuleHandle 等依赖模块表的 API。
    if (reason == DLL_PROCESS_ATTACH) {
        char buf[64];
        _snprintf_s(buf, _countof(buf), _TRUNCATE, "PEHookDemo.dll loaded (PID=%lu)\n", GetCurrentProcessId());
        OutputDebugStringA(buf);
    }
    return TRUE;
}
