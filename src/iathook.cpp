// iathook.cpp - IAT Hook 实现
//
// 原理（对应 Ring3导入表Hook/Dll/Dll.cpp 的 Ring3ImportHook 思路）：
//   从模块基址取 IMAGE_IMPORT_DESCRIPTOR，按 Descriptor->Name 匹配模块名，
//   遍历 FirstThunk 找到目标函数槽，VirtualProtect 置 PAGE_READWRITE，
//   写入新函数地址，再恢复原保护属性。
#include "iathook.h"
#include "common.h"

namespace {

IMAGE_NT_HEADERS* GetNtHeaders(HMODULE hMod)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    return nt;
}

// 在 hMod 的导入表中查找 funcName 的 IAT 槽地址
void** FindIatSlot(HMODULE hMod, const char* funcName)
{
    IMAGE_NT_HEADERS* nt = GetNtHeaders(hMod);
    if (!nt)
        return NULL;
    DWORD impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRva)
        return NULL;
    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hMod + impRva);
    for (; imp->Name; ++imp) {
        // 槽内存放的是函数指针，直接按字节比较 AddressOfData 指向的名称
        const IMAGE_THUNK_DATA* othunk = imp->OriginalFirstThunk
            ? (const IMAGE_THUNK_DATA*)((BYTE*)hMod + imp->OriginalFirstThunk)
            : (const IMAGE_THUNK_DATA*)((BYTE*)hMod + imp->FirstThunk);
        IMAGE_THUNK_DATA* ithunk = (IMAGE_THUNK_DATA*)((BYTE*)hMod + imp->FirstThunk);
        for (; othunk->u1.AddressOfData; ++othunk, ++ithunk) {
            if (IMAGE_SNAP_BY_ORDINAL(othunk->u1.Ordinal))
                continue;
            IMAGE_IMPORT_BY_NAME* ibn =
                (IMAGE_IMPORT_BY_NAME*)((BYTE*)hMod + othunk->u1.AddressOfData);
            if (_stricmp((const char*)ibn->Name, funcName) == 0)
                return (void**)&ithunk->u1.Function;
        }
    }
    return NULL;
}

} // namespace

bool IATHook_ReplaceInModule(HMODULE hMod, const char* funcName,
                             void* pFake, void** ppOriginal)
{
    if (!hMod || !funcName || !pFake || !ppOriginal)
        return false;

    void** slot = FindIatSlot(hMod, funcName);
    if (!slot) {
        LOG_ERR("IAT Hook: 模块 %p 中 %s 未找到导入槽", (void*)hMod, funcName);
        return false;
    }

    // 页面置可写，写入新地址，恢复保护
    DWORD oldProtect = 0;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect))
        return false;
    *ppOriginal = *slot;
    *slot = pFake;
    VirtualProtect(slot, sizeof(void*), oldProtect, &oldProtect);

    LOG("IAT Hook: %s -> %p (原 %p)", funcName, pFake, *ppOriginal);
    return true;
}

bool IATHook_Replace(const char* moduleName, const char* funcName,
                     void* pFake, void** ppOriginal)
{
    if (!moduleName || !funcName || !pFake || !ppOriginal)
        return false;

    // moduleName 已加载则直接取；否则尝试按文件名加载
    HMODULE hMod = GetModuleHandleA(moduleName);
    if (!hMod)
        hMod = LoadLibraryA(moduleName);
    if (!hMod) {
        LOG_ERR("IAT Hook: 模块 %s 不可用", moduleName);
        return false;
    }
    return IATHook_ReplaceInModule(hMod, funcName, pFake, ppOriginal);
}

bool IATHook_Restore(const char* moduleName, const char* funcName, void* pFake)
{
    HMODULE hMod = GetModuleHandleA(moduleName);
    if (!hMod)
        return false;
    void** slot = FindIatSlot(hMod, funcName);
    if (!slot)
        return false;
    if (*slot != pFake) {
        LOG_ERR("IAT 恢复: 槽当前值 %p 与 pFake %p 不符，跳过", *slot, pFake);
        return false;
    }
    DWORD oldProtect = 0;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect))
        return false;
    *slot = NULL; // 由调用方回填原始值
    VirtualProtect(slot, sizeof(void*), oldProtect, &oldProtect);
    return true;
}
