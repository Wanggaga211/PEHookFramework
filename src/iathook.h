// iathook.h - IAT Hook（导入地址表替换）
#pragma once
#ifndef PEHOOK_IATHOOK_H
#define PEHOOK_IATHOOK_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// 把 moduleName 模块 IAT 中 funcName 的槽替换为 pFake，原地址存入 ppOriginal。
// 对应简历「IAT Hook/恢复」：VirtualProtect 改写 + 恢复保护。
bool IATHook_Replace(const char* moduleName, const char* funcName,
                     void* pFake, void** ppOriginal);

// 指定模块句柄版本（适用于反射加载等不在系统模块表的模块）
bool IATHook_ReplaceInModule(HMODULE hMod, const char* funcName,
                             void* pFake, void** ppOriginal);

// 恢复某 IAT 槽（把 pFake 换回 ppOriginal）
bool IATHook_Restore(const char* moduleName, const char* funcName, void* pFake);

#ifdef __cplusplus
}
#endif

#endif
