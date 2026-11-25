// vthook.cpp - VT Hook 实现
//
// 原理：对象内存前 PTR_SZ 字节是指向虚函数表(vtable)的指针；
//   vtable 每个槽位是一个函数指针。把目标槽位改写成我们的 Detour 即可
//   劫持所有该类型的虚调用（同一 vtable 共享）。
#include "vthook.h"
#include "common.h"

bool VTHook_Replace(void* pObj, size_t vtableIndex, void* pFake, void** ppOriginal)
{
    if (!pObj || !pFake || !ppOriginal)
        return false;

    // 1) 读对象虚表指针
    void** vtable = NULL;
    memcpy(&vtable, pObj, PTR_SZ);
    if (!vtable)
        return false;

    // 2) 目标槽地址
    void** slot = &vtable[vtableIndex];

    // 3) 页面置可写后替换
    DWORD oldProtect = 0;
    if (!VirtualProtect(slot, PTR_SZ, PAGE_READWRITE, &oldProtect))
        return false;
    *ppOriginal = *slot;
    *slot = pFake;
    VirtualProtect(slot, PTR_SZ, oldProtect, &oldProtect);

    LOG("VTHook: 槽[%u] %p -> %p (原 %p)", (unsigned)vtableIndex, slot, pFake, *ppOriginal);
    return true;
}
