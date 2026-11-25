// reflective.cpp - 反射式 DLL 加载实现
//
// 核心流程（对应简历中「反射式DLL加载：内存加载PE并修复重定位表」）：
//   PE 文件原始字节 -> 按节对齐映射到内存 -> 修复重定位(Delta) -> 修复导入(IAT) -> DllMain
#include "reflective.h"
#include "common.h"

namespace {

// 从任意 PE 头（32/64 可选头）抽取本框架需要的字段
struct PeInfo {
    WORD   magic;          // IMAGE_NT_OPTIONAL_HDR32_MAGIC / 64
    uintptr_t imageBase;
    DWORD  sizeOfImage;
    DWORD  sizeOfHeaders;
    WORD   numSections;
    DWORD  entryRva;
    DWORD  relocRva, relocSize;
    DWORD  importRva;
    const IMAGE_SECTION_HEADER* firstSection;
};

bool GetPeInfo(const IMAGE_NT_HEADERS* nt, PeInfo& info)
{
    WORD magic = nt->OptionalHeader.Magic;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const IMAGE_NT_HEADERS32* n = (const IMAGE_NT_HEADERS32*)nt;
        info.magic = magic;
        info.imageBase = n->OptionalHeader.ImageBase;
        info.sizeOfImage = n->OptionalHeader.SizeOfImage;
        info.sizeOfHeaders = n->OptionalHeader.SizeOfHeaders;
        info.numSections = n->FileHeader.NumberOfSections;
        info.entryRva = n->OptionalHeader.AddressOfEntryPoint;
        info.relocRva = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        info.relocSize = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        info.importRva = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        info.firstSection = IMAGE_FIRST_SECTION(n);
        return true;
    }
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_NT_HEADERS64* n = (const IMAGE_NT_HEADERS64*)nt;
        info.magic = magic;
        info.imageBase = n->OptionalHeader.ImageBase;
        info.sizeOfImage = n->OptionalHeader.SizeOfImage;
        info.sizeOfHeaders = n->OptionalHeader.SizeOfHeaders;
        info.numSections = n->FileHeader.NumberOfSections;
        info.entryRva = n->OptionalHeader.AddressOfEntryPoint;
        info.relocRva = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        info.relocSize = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        info.importRva = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        info.firstSection = IMAGE_FIRST_SECTION(n);
        return true;
    }
    return false;
}

// 修复一个重定位项（类型按镜像 Magic 区分：PE32=HIGHLOW / PE32+=DIR64）
void FixRelocItem(uintptr_t delta, WORD type, void* addr)
{
    switch (type) {
    case IMAGE_REL_BASED_HIGHLOW:   // 3: 32 位绝对地址
        *(uint32_t*)addr += (uint32_t)delta;
        break;
    case IMAGE_REL_BASED_DIR64:     // 10: 64 位绝对地址
        *(uint64_t*)addr += (uint64_t)delta;
        break;
    case IMAGE_REL_BASED_ABSOLUTE:  // 0: 仅用于对齐，忽略
    case IMAGE_REL_BASED_HIGH:
    case IMAGE_REL_BASED_LOW:
        break;
    default:
        // 其余类型（HIGH/LOW/HIGHADJ 等）本框架未覆盖，记录后跳过
        break;
    }
}

} // namespace

HMODULE LoadLibraryFromMemory(const void* pFileData)
{
    if (!pFileData)
        return NULL;

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)pFileData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)((const BYTE*)pFileData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    PeInfo pi;
    if (!GetPeInfo(nt, pi))
        return NULL;

    // 1) 按 SizeOfImage 分配（SectionAlignment 对齐）
    BYTE* base = (BYTE*)VirtualAlloc(NULL, pi.sizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base)
        return NULL;

    // 2) 拷贝文件头与各节（映射节到虚拟地址）
    memcpy(base, pFileData, min(pi.sizeOfHeaders, pi.sizeOfImage));

    const IMAGE_SECTION_HEADER* sec = pi.firstSection;
    for (WORD i = 0; i < pi.numSections; ++i, ++sec) {
        if (sec->SizeOfRawData == 0)
            continue;
        BYTE* dst = base + sec->VirtualAddress;
        const BYTE* src = (const BYTE*)pFileData + sec->PointerToRawData;
        // 拷贝原始数据；VirtualSize 大于 RawSize 的部分保持 0（VirtualAlloc 已清零）
        memcpy(dst, src, min(sec->SizeOfRawData, sec->Misc.VirtualSize));
    }

    // 3) 修复基址重定位表
    //    Delta = 新基址 - 镜像基址（对应 FixProcessBaseRelocationTable 的 Delta 计算）
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) &&
        pi.relocRva && pi.relocSize) {
        uintptr_t delta = (uintptr_t)base - pi.imageBase;
        BYTE* reloc = base + pi.relocRva;
        BYTE* end = reloc + pi.relocSize;
        DWORD blocks = 0;
        while (reloc + sizeof(IMAGE_BASE_RELOCATION) <= end) {
            IMAGE_BASE_RELOCATION* blk = (IMAGE_BASE_RELOCATION*)reloc;
            if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                (DWORD)(end - reloc) < blk->SizeOfBlock)
                break;
            DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* items = (WORD*)(reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < cnt; ++i) {
                WORD type = items[i] >> 12;
                WORD off  = items[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_ABSOLUTE)
                    continue;
                // 目标地址 = 镜像基址 + 块声明的页面RVA + 页内偏移
                FixRelocItem(delta, type, base + blk->VirtualAddress + off);
            }
            reloc += blk->SizeOfBlock;
            ++blocks;
            if (blocks > 64)
                break;
        }
    }

    // 4) 修复导入表（IAT 回填）
    if (pi.importRva) {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + pi.importRva);
        for (; imp->Name; ++imp) {
            const char* modName = (const char*)(base + imp->Name);
            HMODULE hMod = LoadLibraryA(modName);
            if (!hMod) {
                LOG_ERR("反射加载: 导入模块 %s 加载失败", modName);
                continue;
            }
            // OriginalFirstThunk 存在则按它取函数名/序号，否则用 FirstThunk
            const IMAGE_THUNK_DATA* othunk = imp->OriginalFirstThunk
                ? (const IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk)
                : (const IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
            IMAGE_THUNK_DATA* ithunk = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
            for (; othunk->u1.AddressOfData; ++othunk, ++ithunk) {
                FARPROC fn = NULL;
                if (IMAGE_SNAP_BY_ORDINAL(othunk->u1.Ordinal)) {
                    fn = GetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(othunk->u1.Ordinal));
                } else {
                    const IMAGE_IMPORT_BY_NAME* ibn =
                        (const IMAGE_IMPORT_BY_NAME*)(base + othunk->u1.AddressOfData);
                    fn = GetProcAddress(hMod, (LPCSTR)ibn->Name);
                }
                if (fn)
                    ithunk->u1.Function = (ULONG_PTR)fn;
                else
                    LOG_ERR("反射加载: %s!函数解析失败", modName);
            }
        }
    }

    // 5) 调用 DllMain(PROCESS_ATTACH)
    HINSTANCE hinst = (HINSTANCE)base;
    if (pi.entryRva) {
        typedef BOOL(WINAPI* DllMain_t)(HINSTANCE, DWORD, LPVOID);
        DllMain_t entry = (DllMain_t)(base + pi.entryRva);
        if (!entry(hinst, DLL_PROCESS_ATTACH, NULL)) {
            VirtualFree(base, 0, MEM_RELEASE);
            return NULL;
        }
    }
    return hinst;
}

HMODULE LoadLibraryFromMemoryFile(const char* dllPath)
{
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return NULL;
    DWORD size = GetFileSize(hFile, NULL);
    if (size == 0 || size == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return NULL;
    }
    BYTE* buf = (BYTE*)malloc(size);
    if (!buf) {
        CloseHandle(hFile);
        return NULL;
    }
    DWORD rd = 0;
    BOOL ok = ReadFile(hFile, buf, size, &rd, NULL);
    CloseHandle(hFile);
    if (!ok || rd != size) {
        free(buf);
        return NULL;
    }
    HMODULE m = LoadLibraryFromMemory(buf);
    free(buf);
    return m;
}

// 遍历导出表按名字查函数（反射模块专用，GetProcAddress 依赖加载器模块列表）
FARPROC FindExport(HMODULE hModule, const char* name)
{
    const BYTE* b = (const BYTE*)hModule;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)b;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(b + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    DWORD expRva = 0;
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_NT_HEADERS64* n64 = (const IMAGE_NT_HEADERS64*)nt;
        expRva = n64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    } else {
        const IMAGE_NT_HEADERS32* n32 = (const IMAGE_NT_HEADERS32*)nt;
        expRva = n32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }
    if (!expRva)
        return NULL;

    const IMAGE_EXPORT_DIRECTORY* exp =
        (const IMAGE_EXPORT_DIRECTORY*)(b + expRva);
    const DWORD* names = (const DWORD*)(b + exp->AddressOfNames);
    const WORD*  ords  = (const WORD*)(b + exp->AddressOfNameOrdinals);
    const DWORD* funcs = (const DWORD*)(b + exp->AddressOfFunctions);
    const bool is32 = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* n = (const char*)(b + names[i]);
        if (strcmp(n, name) == 0)
            return (FARPROC)(b + funcs[ords[i]]);
        // x86 下 __declspec(dllexport) + stdcall 导出为修饰名 "_Name@参数字节数"，
        // 允许调用方直接传裸名（与 x64 一致）。
        if (is32 && name[0] != '_') {
            size_t len = strlen(name);
            if (n[0] == '_' && strncmp(n + 1, name, len) == 0 && n[len + 1] == '@')
                return (FARPROC)(b + funcs[ords[i]]);
        }
    }
    return NULL;
}
