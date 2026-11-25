// loader_stub.cpp - LoaderStub.dll：远程反射加载的引导模块
// 被注入目标进程后，其导出 LoadImageFromMemory 在目标进程内完成
// 「内存映射 PE + 修复重定位 + 修复导入 + DllMain」的完整加载，返回模块句柄。
#include "reflective.h"

extern "C" __declspec(dllexport) HMODULE WINAPI LoadImageFromMemory(const BYTE* pFileImage)
{
    if (!pFileImage)
        return NULL;
    // 直接复用反射加载核心逻辑（同一份 reflective.cpp 编译进本 DLL）
    return ::LoadLibraryFromMemory(pFileImage);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    (void)reason;
    return TRUE;
}
