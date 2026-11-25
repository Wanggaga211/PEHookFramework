// contexthook.h - EIP/RIP Hook（线程上下文注入）
#pragma once
#ifndef PEHOOK_CONTEXTHOOK_H
#define PEHOOK_CONTEXTHOOK_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// 挂起线程 -> 保存上下文 -> 把指令指针(Rip/Eip)重定向到 pTarget。
// 之后恢复线程即从 pTarget 继续执行（可在 pTarget 内恢复原上下文实现「透视」）。
bool ContextHook_Redirect(HANDLE hThread, void* pTarget, CONTEXT* pSaved);

// 把已保存的上下文写回线程（恢复指令指针等全部寄存器）
bool ContextHook_Restore(HANDLE hThread, const CONTEXT* pSaved);

#ifdef __cplusplus
}
#endif

#endif
