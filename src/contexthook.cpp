// contexthook.cpp - EIP/RIP Hook 实现
//
// 对应简历「线程上下文注入」：GetThreadContext/SetThreadContext +
//   SuspendThread/ResumeThread，把指令指针改写到目标地址。
#include "contexthook.h"
#include "common.h"

bool ContextHook_Redirect(HANDLE hThread, void* pTarget, CONTEXT* pSaved)
{
    if (!hThread || !pTarget || !pSaved)
        return false;

    SuspendThread(hThread); // 挂起，保证上下文一致

    pSaved->ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, pSaved)) {
        LOG_ERR("GetThreadContext 失败: %lu", GetLastError());
        ResumeThread(hThread);
        return false;
    }

    CONTEXT ctx = *pSaved;
#ifdef _WIN64
    ctx.Rip = (DWORD64)pTarget;
#else
    ctx.Eip = (DWORD)pTarget;
#endif

    if (!SetThreadContext(hThread, &ctx)) {
        LOG_ERR("SetThreadContext 失败: %lu", GetLastError());
        ResumeThread(hThread);
        return false;
    }

    ResumeThread(hThread);
    LOG("ContextHook: 指令指针已重定向到 %p", pTarget);
    return true;
}

bool ContextHook_Restore(HANDLE hThread, const CONTEXT* pSaved)
{
    if (!hThread || !pSaved)
        return false;

    SuspendThread(hThread);
    CONTEXT ctx = *pSaved;
    ctx.ContextFlags = CONTEXT_FULL;
    BOOL ok = SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);

    LOG("ContextHook: 上下文已恢复");
    return ok != FALSE;
}
