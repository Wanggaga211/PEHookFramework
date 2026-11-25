// reflective.h - 反射式 DLL 加载（内存加载 PE 镜像，不落地磁盘）
#pragma once
#ifndef PEHOOK_REFLECTIVE_H
#define PEHOOK_REFLECTIVE_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// 从内存中的 PE 文件原始字节加载 DLL（当前进程），返回模块句柄。
// pFileData 指向完整 PE 文件（FileAlignment 布局），函数会：
//   1. 按 SizeOfImage 分配内存并映射各节（SectionAlignment）
//   2. 修复基址重定位表（Delta = 新基址 - ImageBase）
//   3. 修复导入表（LoadLibraryA + GetProcAddress 回填 IAT）
//   4. 调用 DllMain(DLL_PROCESS_ATTACH)
// 失败返回 NULL。
HMODULE LoadLibraryFromMemory(const void* pFileData);

// 从磁盘读取文件并反射加载，等价 LoadLibraryFromMemory(readfile(path))
HMODULE LoadLibraryFromMemoryFile(const char* dllPath);

// 在任意内存 PE 镜像（含反射加载的模块，不在系统模块表）中按名字查找导出函数。
// 兼容 x86/x64（按 OptionalHeader.Magic 分支解析）。
// 反射加载的模块无法用 GetProcAddress（其依赖加载器模块列表），必须用本函数。
FARPROC FindExport(HMODULE hModule, const char* name);

#ifdef __cplusplus
}
#endif

#endif
