// inlinehook.cpp - Inline Hook 实现（Hde32/64 指令解码 + 蹦床）
//
// 对应简历「基于Hde32/64编写Inline Hook（指令解码、跳转修正、蹦床）」：
//   1. 用 Hde32/Hde64 反汇编目标函数头部，确定完整的指令边界（长度 >= patch 大小）
//   2. 把被覆盖指令原样搬入可执行内存（蹦床），尾部追加跳回原函数剩余部分
//   3. 在目标函数头部写入绝对跳转（x64 12 字节 / x86 5 字节）到 Detour
#include "inlinehook.h"
#include "common.h"
#ifdef _WIN64
#include "../hde/hde64.h"
#else
#include "../hde/hde32.h"
#endif

namespace {

const size_t kPatchSize =
#ifdef _WIN64
    12; // 48 B8 imm64 / FF E0
#else
    5;  // E9 rel32
#endif

// 用 Hde 解码并累计完整指令长度（>= patchSize 即停止），失败返回 0
size_t CalcCodedSize(const BYTE* code)
{
    size_t total = 0;
    while (total < kPatchSize) {
        unsigned len = 0;
#ifdef _WIN64
        hde64s hs;
        len = hde64_disasm(code + total, &hs);
#else
        hde32s hs;
        len = hde32_disasm(code + total, &hs);
#endif
        if (len == 0)
            return 0; // 非法指令/越界
        total += len;
    }
    return total;
}

// 蹦床尾部跳回原函数剩余部分（pTarget + codedSize）
void AppendJumpBack(BYTE* p, size_t* off, const BYTE* pTarget, size_t codedSize)
{
#ifdef _WIN64
    // mov rax, imm64; jmp rax
    p[(*off)++] = 0x48;
    p[(*off)++] = 0xB8;
    *(uint64_t*)(p + *off) = (uint64_t)(pTarget + codedSize);
    *off += 8;
    p[(*off)++] = 0xFF;
    p[(*off)++] = 0xE0;
#else
    // E9 rel32
    p[(*off)++] = 0xE9;
    int32_t rel = (int32_t)((uintptr_t)(pTarget + codedSize) - ((uintptr_t)(p + *off) + 4));
    *(int32_t*)(p + *off) = rel;
    *off += 4;
#endif
}

} // namespace

bool InlineHook_Install(void* pTarget, void* pDetour, void** ppTrampoline)
{
    if (!pTarget || !pDetour || !ppTrampoline)
        return false;

    BYTE* code = (BYTE*)pTarget;

    // 0) 简单防御：函数首字节为 ret 时无法安全覆盖
    if (code[0] == 0xC3)
        return false;

    // 1) 指令解码，确定被覆盖的完整字节数
    size_t codedSize = CalcCodedSize(code);
    if (codedSize < kPatchSize)
        return false;

    // 2) 分配蹦床（可执行）
    BYTE* tramp = (BYTE*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!tramp)
        return false;

    // 3) 拷贝被覆盖指令
    memcpy(tramp, code, codedSize);
    size_t off = codedSize;
    AppendJumpBack(tramp, &off, code, codedSize);

    // 4) 保存原字节并写入跳转到 Detour
    DWORD oldProtect = 0;
    if (!VirtualProtect(code, kPatchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        VirtualFree(tramp, 0, MEM_RELEASE);
        return false;
    }
#ifdef _WIN64
    code[0] = 0x48; code[1] = 0xB8;
    *(uint64_t*)(code + 2) = (uint64_t)pDetour;
    code[10] = 0xFF; code[11] = 0xE0;
#else
    code[0] = 0xE9;
    *(int32_t*)(code + 1) = (int32_t)((uintptr_t)pDetour - ((uintptr_t)pTarget + 5));
#endif
    VirtualProtect(code, kPatchSize, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), code, kPatchSize);

    *ppTrampoline = tramp;
    LOG("InlineHook: %p -> %p (蹦床 %p, 覆盖 %u 字节)", pTarget, pDetour,
        tramp, (unsigned)codedSize);
    return true;
}

bool InlineHook_Uninstall(void* pTarget, void* pDetour, void* pTrampoline)
{
    (void)pDetour;
    if (!pTarget || !pTrampoline)
        return false;
    BYTE* code = (BYTE*)pTarget;

    // 从蹦床取回原字节（蹦床前 kPatchSize 字节就是被覆盖的原始指令）
    DWORD oldProtect = 0;
    if (!VirtualProtect(code, kPatchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;
    memcpy(code, pTrampoline, kPatchSize);
    VirtualProtect(code, kPatchSize, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), code, kPatchSize);

    VirtualFree(pTrampoline, 0, MEM_RELEASE);
    LOG("InlineHook: 已还原 %p", pTarget);
    return true;
}
