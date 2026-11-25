// vthook.h - VT Hook（虚表替换）
#pragma once
#ifndef PEHOOK_VTHOOK_H
#define PEHOOK_VTHOOK_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// 替换对象 pObj 虚表第 vtableIndex 个槽位为 pFake，原槽位存入 ppOriginal。
bool VTHook_Replace(void* pObj, size_t vtableIndex, void* pFake, void** ppOriginal);

#ifdef __cplusplus
}
#endif

#endif
