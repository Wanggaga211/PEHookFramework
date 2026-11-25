// inject.cpp - 六种用户态注入实现
#include "inject.h"
#include "common.h"

#include <tlhelp32.h>

namespace {

// ---------- 动态取 ntdll 例程（避免静态链接） ----------
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* RtlCreateUserThread_t)(
    HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PVOID, PVOID, PHANDLE, PVOID);

NtCreateThreadEx_t GetNtCreateThreadEx()
{
    static NtCreateThreadEx_t fn = (NtCreateThreadEx_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    return fn;
}

RtlCreateUserThread_t GetRtlCreateUserThread()
{
    static RtlCreateUserThread_t fn = (RtlCreateUserThread_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");
    return fn;
}

// ---------- 通用：远程分配 + 写路径 + 等待退出码 ----------
// 在目标进程写入 dll 全路径，返回远程字符串地址；失败 NULL
LPVOID WriteRemoteString(HANDLE hProc, const char* dllPath)
{
    size_t len = strlen(dllPath) + 1;
    LPVOID remote = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote)
        return NULL;
    if (!WriteProcessMemory(hProc, remote, dllPath, len, NULL)) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return NULL;
    }
    return remote;
}

// 通用：远端线程执行 LoadLibraryA(dllPath)，等待完成，返回远程 HMODULE
HMODULE RunLoadLibrary(HANDLE hProc, const char* dllPath)
{
    LPVOID remotePath = WriteRemoteString(hProc, dllPath);
    if (!remotePath)
        return NULL;
    FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pLoadLibrary, remotePath, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        return NULL;
    }
    WaitForSingleObject(hThread, 10000);
    DWORD code = 0;
    GetExitCodeThread(hThread, &code);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    return (HMODULE)(UINT_PTR)code;
}

// 目标进程主线程（QueueUserAPC 用）
DWORD GetMainThreadId(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    DWORD tid = 0;
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                // 取该进程第一个线程即可（主线程通常最先创建）
                tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

// ---------- 单种注入实现 ----------
bool DoCreateRemoteThread(DWORD pid, const char* dllPath)
{
    HANDLE hProc = OpenProcess(PROC_ALL_REQUIRED, FALSE, pid);
    if (!hProc) {
        LOG_ERR("OpenProcess(%lu) 失败: %lu", pid, GetLastError());
        return false;
    }
    HMODULE m = RunLoadLibrary(hProc, dllPath);
    CloseHandle(hProc);
    if (!m) {
        LOG_ERR("CreateRemoteThread 注入失败");
        return false;
    }
    LOG("CreateRemoteThread 注入成功, 远程模块=%p", (void*)m);
    return true;
}

bool DoNtCreateThreadEx(DWORD pid, const char* dllPath)
{
    NtCreateThreadEx_t pNt = GetNtCreateThreadEx();
    if (!pNt) {
        LOG_ERR("无法获取 NtCreateThreadEx");
        return false;
    }
    HANDLE hProc = OpenProcess(PROC_ALL_REQUIRED, FALSE, pid);
    if (!hProc)
        return false;
    LPVOID remotePath = WriteRemoteString(hProc, dllPath);
    if (!remotePath) {
        CloseHandle(hProc);
        return false;
    }
    FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hThread = NULL;
    NTSTATUS st = pNt(&hThread, THREAD_ALL_ACCESS, NULL, hProc,
                      (LPTHREAD_START_ROUTINE)pLoadLibrary, remotePath,
                      0, 0, 0, 0, NULL);
    if (st != 0) {
        LOG_ERR("NtCreateThreadEx 失败, NTSTATUS=0x%08X", (unsigned)st);
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    WaitForSingleObject(hThread, 10000);
    DWORD code = 0;
    GetExitCodeThread(hThread, &code);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProc);
    LOG("NtCreateThreadEx 注入成功, 远程模块=%p", (void*)(UINT_PTR)code);
    return code != 0;
}

bool DoQueueUserAPC(DWORD pid, const char* dllPath)
{
    HANDLE hProc = OpenProcess(PROC_ALL_REQUIRED, FALSE, pid);
    if (!hProc)
        return false;
    LPVOID remotePath = WriteRemoteString(hProc, dllPath);
    if (!remotePath) {
        CloseHandle(hProc);
        return false;
    }
    FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    DWORD tid = GetMainThreadId(pid);
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hThread) {
        LOG_ERR("打开目标线程 %lu 失败", tid);
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    // APC 需要线程进入可告警等待状态；若线程忙会延迟执行
    if (!QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)remotePath)) {
        LOG_ERR("QueueUserAPC 失败: %lu", GetLastError());
        CloseHandle(hThread);
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    LOG("QueueUserAPC 已入队到线程 %lu, 将在其可告警等待时执行", tid);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return true;
}

bool DoRtlCreateUserThread(DWORD pid, const char* dllPath)
{
    RtlCreateUserThread_t pRtl = GetRtlCreateUserThread();
    if (!pRtl) {
        LOG_ERR("无法获取 RtlCreateUserThread");
        return false;
    }
    HANDLE hProc = OpenProcess(PROC_ALL_REQUIRED, FALSE, pid);
    if (!hProc)
        return false;
    LPVOID remotePath = WriteRemoteString(hProc, dllPath);
    if (!remotePath) {
        CloseHandle(hProc);
        return false;
    }
    FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hThread = NULL;
    NTSTATUS st = pRtl(hProc, NULL, 0, 0, NULL,
                       (LPTHREAD_START_ROUTINE)pLoadLibrary, remotePath, &hThread, NULL);
    if (st != 0) {
        LOG_ERR("RtlCreateUserThread 失败, NTSTATUS=0x%08X", (unsigned)st);
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    WaitForSingleObject(hThread, 10000);
    DWORD code = 0;
    GetExitCodeThread(hThread, &code);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProc);
    LOG("RtlCreateUserThread 注入成功, 远程模块=%p", (void*)(UINT_PTR)code);
    return code != 0;
}

bool DoSetWindowsHookEx(DWORD pid, const char* dllPath)
{
    // 钩子回调必须位于被注入 DLL 内。流程：
    //   1. 普通注入把钩子 DLL 加载进目标进程
    //   2. SetWindowsHookEx(WH_GETMESSAGE, 目标进程内 HookProc, hDll, 目标线程)
    HMODULE m = RunLoadLibrary(OpenProcess(PROC_ALL_REQUIRED, FALSE, pid), dllPath);
    if (!m) {
        LOG_ERR("SetWindowsHookEx 前置注入失败");
        return false;
    }
    HMODULE hLocal = LoadLibraryA(dllPath);
    if (!hLocal) {
        LOG_ERR("本进程加载钩子 DLL 失败");
        return false;
    }
    HOOKPROC pProc = (HOOKPROC)GetProcAddress(hLocal, "HookProc");
    if (!pProc) {
        LOG_ERR("钩子 DLL 未导出 HookProc");
        return false;
    }
    DWORD tid = GetMainThreadId(pid);
    HHOOK hHook = SetWindowsHookExW(WH_GETMESSAGE, pProc, hLocal, tid);
    if (!hHook) {
        LOG_ERR("SetWindowsHookEx 失败: %lu", GetLastError());
        return false;
    }
    LOG("SetWindowsHookEx 成功, 钩子句柄=%p, 目标线程=%lu", (void*)hHook, tid);
    // 演示场景保留钩子；进程退出自动清理
    return true;
}

bool DoAppInitDlls(const char* dllPath, bool enable)
{
    // 注册表注入：HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
    //   AppInit_DLLs: 要注入的 DLL 完整路径（空格分隔多个）
    //   LoadAppInit_DLLs: 1 启用 / 0 禁用（Win8+ 还需 SecureBoot 关闭才会生效）
    const char* keyPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    HKEY hKey = NULL;
    LONG st = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE, &hKey);
    if (st != ERROR_SUCCESS) {
        LOG_ERR("打开注册表 %s 失败(可能需要管理员): %ld", keyPath, st);
        return false;
    }
    bool ok = false;
    if (enable) {
        st = RegSetValueExA(hKey, "AppInit_DLLs", 0, REG_SZ,
                            (const BYTE*)dllPath, (DWORD)(strlen(dllPath) + 1));
        DWORD one = 1;
        if (st == ERROR_SUCCESS)
            st = RegSetValueExA(hKey, "LoadAppInit_DLLs", 0, REG_DWORD, (const BYTE*)&one, sizeof(one));
        ok = (st == ERROR_SUCCESS);
    } else {
        st = RegSetValueExA(hKey, "LoadAppInit_DLLs", 0, REG_DWORD,
                            (const BYTE*)"\x00\x00\x00\x00", sizeof(DWORD));
        ok = (st == ERROR_SUCCESS);
    }
    RegCloseKey(hKey);
    if (!ok)
        LOG_ERR("写入 AppInit_DLLs 失败: %ld", st);
    else
        LOG("AppInit_DLLs 已%s: %s", enable ? "写入" : "停用", dllPath);
    return ok;
}

// ---------- 远程反射加载（LoaderStub 两阶段） ----------
// 阶段1: 远程分配内存写入目标 DLL 文件原始字节（FileAlignment 布局）
// 阶段2: 把 LoaderStub.dll 注入目标进程，其导出 LoadImageFromMemory
//        (基址+RVA 定位) 在目标进程内完成内存映射 -> 返回 HMODULE
extern "C" HMODULE WINAPI LoadImageFromMemory(const BYTE* pFileImage); // 声明自 loader_stub

bool DoReflective(DWORD pid, const char* dllPath, const char* stubPath)
{
    HANDLE hProc = OpenProcess(PROC_ALL_REQUIRED, FALSE, pid);
    if (!hProc) {
        LOG_ERR("OpenProcess(%lu) 失败", pid);
        return false;
    }

    // 读目标 DLL 文件
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProc);
        return false;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* fileBuf = (BYTE*)malloc(fileSize);
    DWORD rd = 0;
    if (!fileBuf || !ReadFile(hFile, fileBuf, fileSize, &rd, NULL)) {
        if (fileBuf) free(fileBuf);
        CloseHandle(hFile);
        CloseHandle(hProc);
        return false;
    }
    CloseHandle(hFile);

    // 阶段1: 远程写 PE 原始字节
    LPVOID remoteImage = VirtualAllocEx(hProc, NULL, fileSize,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteImage ||
        !WriteProcessMemory(hProc, remoteImage, fileBuf, fileSize, NULL)) {
        LOG_ERR("远程写入 PE 镜像失败");
        if (remoteImage) VirtualFreeEx(hProc, remoteImage, 0, MEM_RELEASE);
        free(fileBuf);
        CloseHandle(hProc);
        return false;
    }
    free(fileBuf);

    // 阶段2: 注入 LoaderStub 并在远程执行 LoadImageFromMemory(remoteImage)
    HMODULE remoteStub = RunLoadLibrary(hProc, stubPath);
    if (!remoteStub) {
        LOG_ERR("LoaderStub 注入失败");
        VirtualFreeEx(hProc, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // 导出 RVA（本地 Stub 基址 + RVA = 远程基址 + RVA，RVA 对同一 DLL 固定）
    HMODULE hLocalStub = GetModuleHandleA(stubPath);
    if (!hLocalStub)
        hLocalStub = LoadLibraryA(stubPath);
    FARPROC pLocal = GetProcAddress(hLocalStub, "LoadImageFromMemory");
    if (!pLocal) {
        LOG_ERR("LoaderStub 无导出 LoadImageFromMemory");
        VirtualFreeEx(hProc, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    ULONG_PTR rva = (ULONG_PTR)pLocal - (ULONG_PTR)hLocalStub;
    void* remoteEntry = (void*)((ULONG_PTR)remoteStub + rva);

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remoteEntry,
                                        remoteImage, 0, NULL);
    if (!hThread) {
        LOG_ERR("创建远程反射线程失败: %lu", GetLastError());
        VirtualFreeEx(hProc, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    WaitForSingleObject(hThread, 15000);
    DWORD code = 0;
    GetExitCodeThread(hThread, &code);
    CloseHandle(hThread);
    CloseHandle(hProc);
    if (!code) {
        LOG_ERR("远程反射加载失败（目标进程内返回 NULL）");
        return false;
    }
    LOG("远程反射加载成功, 远程模块=%p", (void*)(UINT_PTR)code);
    return true;
}

} // namespace

const char* InjectMethodName(InjectMethod m)
{
    static const char* names[] = {
        "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC",
        "RtlCreateUserThread", "SetWindowsHookEx", "AppInit_DLLs", "Reflective"
    };
    if ((int)m < 0 || m >= INJECT_METHOD_COUNT)
        return "Unknown";
    return names[m];
}

bool InjectIntoProcess(InjectMethod m, DWORD pid, const char* dllPath)
{
    switch (m) {
    case INJECT_CREATE_REMOTE_THREAD: return DoCreateRemoteThread(pid, dllPath);
    case INJECT_NT_CREATE_THREAD_EX:  return DoNtCreateThreadEx(pid, dllPath);
    case INJECT_QUEUE_USER_APC:       return DoQueueUserAPC(pid, dllPath);
    case INJECT_RTL_CREATE_USER_THREAD: return DoRtlCreateUserThread(pid, dllPath);
    case INJECT_SET_WINDOWS_HOOK_EX:  return DoSetWindowsHookEx(pid, dllPath);
    case INJECT_APPINIT_DLLS:         return DoAppInitDlls(dllPath, true);
    case INJECT_REFLECTIVE: {
        // 从 dllPath 推导 stub 路径：同目录下 PEHookLoaderStub.dll
        char stubPath[MAX_PATH];
        strcpy_s(stubPath, dllPath);
        char* slash = strrchr(stubPath, '\\');
        if (slash)
            strcpy_s(slash + 1, MAX_PATH - (slash + 1 - stubPath), "PEHookLoaderStub.dll");
        else
            strcpy_s(stubPath, "PEHookLoaderStub.dll");
        return DoReflective(pid, dllPath, stubPath);
    }
    default: return false;
    }
}

bool InjectViaAppInitDlls(const char* dllPath, bool enable)
{
    return DoAppInitDlls(dllPath, enable);
}
