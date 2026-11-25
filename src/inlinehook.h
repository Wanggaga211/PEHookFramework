// inlinehook.h - Inline Hook（指令级，Hde32/64 解码 + 蹦床）
#pragma once
#ifndef PEHOOK_INLINEHOOK_H
#define PEHOOK_INLINEHOOK_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// 在 pTarget 函数头安装绝对跳转（x64: mov rax,detour;jmp rax = 12B；
//                              x86: jmp rel32 = 5B）。
// 被覆盖指令复制到可执行蹦床，ppTrampoline 返回蹦床入口（可调用原逻辑）。
bool InlineHook_Install(void* pTarget, void* pDetour, void** ppTrampoline);

// 还原 pTarget 头部字节，释放蹦床
bool InlineHook_Uninstall(void* pTarget, void* pDetour, void* pTrampoline);

#ifdef __cplusplus
}
#endif

#endif
