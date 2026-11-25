// common.h - PEHookFramework 公共头
#pragma once
#ifndef PEHOOK_COMMON_H
#define PEHOOK_COMMON_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

// 输出：控制台 + 调试器双通道，便于注入场景（无控制台）观察
#define LOG(fmt, ...)                                              \
    do {                                                           \
        char _buf[512];                                            \
        _snprintf_s(_buf, _countof(_buf), _TRUNCATE, fmt, ##__VA_ARGS__); \
        printf("%s\n", _buf);                                      \
        fflush(stdout);                                            \
        OutputDebugStringA(_buf);                                  \
    } while (0)

#define LOG_ERR(fmt, ...) LOG("[!] " fmt, ##__VA_ARGS__)

// 进程访问权限（六种注入所需的最小子集，实际以 API 要求为准）
#define PROC_ALL_REQUIRED \
    (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | \
     PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE)

// 对齐辅助
inline SIZE_T AlignUp(SIZE_T v, SIZE_T a) { return (v + a - 1) & ~(a - 1); }
inline SIZE_T AlignDown(SIZE_T v, SIZE_T a) { return v & ~(a - 1); }

// 指针宽度
#ifdef _WIN64
#define PTR_SZ 8ULL
#else
#define PTR_SZ 4ULL
#endif

#endif // PEHOOK_COMMON_H
