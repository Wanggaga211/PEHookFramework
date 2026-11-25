// inject.h - 六种用户态注入 + 远程反射加载
#pragma once
#ifndef PEHOOK_INJECT_H
#define PEHOOK_INJECT_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// 注入方式枚举（对应简历「六种用户态注入」）
typedef enum {
    INJECT_CREATE_REMOTE_THREAD = 0, // 1. CreateRemoteThread + LoadLibraryA
    INJECT_NT_CREATE_THREAD_EX,      // 2. NtCreateThreadEx
    INJECT_QUEUE_USER_APC,           // 3. QueueUserAPC
    INJECT_RTL_CREATE_USER_THREAD,   // 4. RtlCreateUserThread
    INJECT_SET_WINDOWS_HOOK_EX,      // 5. SetWindowsHookEx
    INJECT_APPINIT_DLLS,             // 6. 注册表 AppInit_DLLs
    INJECT_REFLECTIVE,               // 反射式加载（LoaderStub 两阶段）
    INJECT_METHOD_COUNT
} InjectMethod;

const char* InjectMethodName(InjectMethod m);

// 六种注入：把 dllPath 注入 pid 进程
bool InjectIntoProcess(InjectMethod m, DWORD pid, const char* dllPath);

// 注册表 AppInit_DLLs（注入到所有加载 user32 的 GUI 进程，需管理员）
bool InjectViaAppInitDlls(const char* dllPath, bool enable);

#ifdef __cplusplus
}
#endif

#endif
