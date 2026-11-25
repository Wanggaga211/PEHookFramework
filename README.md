# Windows 用户态 PE Hook 与注入框架（Ring3 大型实践）

> 简历项目五实现工程。综合实现六种用户态注入（CreateRemoteThread / NtCreateThreadEx /
> QueueUserAPC / RtlCreateUserThread / SetWindowsHookEx / 注册表 AppInit_DLLs）与
> IAT、Inline、VT、EIP/RIP 四类 Hook 框架，兼容 x86/x64。
>
> 核心职责：实现反射式 DLL 加载（内存加载 PE 并修复重定位表）；基于 Hde32/64 编写
> Inline Hook（指令解码、跳转修正、蹦床）；完成 IAT Hook/恢复、导入表修复、
> VT Hook 与线程上下文注入。

## 目录结构

```
PEHookFramework/
├── build.bat             一键构建脚本（x64 / x86 双架构）
├── src/
│   ├── common.h          公共宏（日志、对齐、指针宽度）
│   ├── reflective.h/.cpp 反射式 DLL 加载 + FindExport（反射模块导出查找）
│   ├── inject.h/.cpp     六种注入 + 远程反射两阶段注入
│   ├── loader_stub.cpp   PEHookLoaderStub.dll（远程反射加载桩）
│   ├── iathook.h/.cpp    IAT Hook / 恢复（支持反射加载模块）
│   ├── inlinehook.h/.cpp Inline Hook（Hde32/64 指令解码 + 蹦床）
│   ├── vthook.h/.cpp     VT Hook（虚表槽位替换）
│   ├── contexthook.h/.cpp 线程上下文注入（EIP/RIP 重定向与恢复）
│   ├── hook_demo.cpp     PEHookDemo.dll（演示与自测目标模块）
│   └── main.cpp          PEHookInjector.exe（CLI 入口 + 本进程全功能自测）
├── hde/                  Hde32/64 反汇编表（MinHook 素材，指令解码用）
└── bin/
    ├── x64/              x64 构建产物
    └── x86/              x86 构建产物
```

## 构建要求

- Visual Studio 2019（含 C++ 桌面开发工具链），`build.bat` 通过 `vswhere` 定位或直接调用
  `VC\Auxiliary\Build\vcvars64.bat / vcvars32.bat`。
- 产物输出到 `bin\x64` / `bin\x86`，各含：
  - `PEHookInjector.exe`  CLI 工具（自测 / 注入 / AppInit 管理）
  - `PEHookDemo.dll`     演示目标模块（自测用，含导出与 HookProc）
  - `PEHookLoaderStub.dll` 远程反射加载桩（含反射加载器实现）

## 快速开始（本进程自测）

```bat
build.bat x64        :: 或 build.bat x86
bin\x64\PEHookInjector.exe selfdemo
```

自测覆盖 5 项，全部通过返回退出码 0：

1. **反射式 DLL 加载**：内存映射 PE → 修复重定位表（Delta 重基）→ 修复导入表（IAT 回填）→ 调 DllMain
2. **IAT Hook**：替换 demo 模块导入表 MessageBoxA 槽，调用原流程验证劫持生效
3. **Inline Hook**：Hde32/64 解码确定完整指令边界 → 覆盖补丁（x64=12B / x86=5B）→ 蹦床调用原逻辑 → 还原
4. **VT Hook**：替换 CConfig 虚表槽 0，验证 GetValue 返回 0xDEAD，保留原槽
5. **Context Hook**：SuspendThread → GetThreadContext → 改写 RIP/EIP 重定向 WorkerThread → 恢复原上下文

## CLI 注入用法

```bat
:: 六种注入 + 远程反射（任选其一）
PEHookInjector.exe inject --method CreateRemoteThread --pid <PID> --dll C:\path\PEHookDemo.dll
PEHookInjector.exe inject --method NtCreateThreadEx --pid <PID> --dll ...
PEHookInjector.exe inject --method QueueUserAPC --pid <PID> --dll ...
PEHookInjector.exe inject --method RtlCreateUserThread --pid <PID> --dll ...
PEHookInjector.exe inject --method SetWindowsHookEx --pid <PID> --dll ...   :: 目标需有 GUI 消息循环，dll 须导出 HookProc
PEHookInjector.exe inject --method AppInit_DLLs --pid <PID> --dll ...       :: 需管理员；Win8+ 需关闭 SecureBoot 才生效
PEHookInjector.exe inject --method Reflective --pid <PID> --dll ...         :: 远程反射两阶段：远程写 PE 字节 -> LoaderStub 入口

:: AppInit_DLLs 注册表管理
PEHookInjector.exe appinit --enable --dll C:\path\PEHookDemo.dll
PEHookInjector.exe appinit --disable --dll C:\path\PEHookDemo.dll
```

## 实现要点

- **反射式加载**：按 `SizeOfImage` 分配 `PAGE_EXECUTE_READWRITE`，映射文件头与各节；重定位
  项目标地址 = 镜像基址 + 块 VirtualAddress + 页内偏移（类型按 Magic 分支：PE32=HIGHLOW /
  PE32+=DIR64）；导入表按 OriginalFirstThunk/FirstThunk 回填。
- **FindExport**：反射模块不在系统模块表，`GetProcAddress` 不可用，故自实现导出表遍历
  （AddressOfNames/NameOrdinals/Functions），并兼容 x86 stdcall 修饰名（`_Name@N`）。
- **Inline Hook**：x64 补丁 12 字节（`mov rax,imm64; jmp rax`），x86 5 字节（`E9 rel32`）；
  蹦床 = 被覆盖指令原样拷贝 + 尾部跳回原函数剩余段；`FlushInstructionCache` 保证指令缓存一致。
- **Nt/Rtl 系 API** 通过 `GetProcAddress` 动态解析（NtCreateThreadEx、RtlCreateUserThread），
  避免静态链接未文档化 API。

## 已验证

- x64 与 x86 双架构编译通过，`selfdemo` 5 项自测全部通过（退出码 0）。
- 反射加载 `Demo_Add(30,12)=42`；IAT 劫持生效；Inline 劫持 + 蹦床 + 还原正确；
  VT 返回 0xDEAD；Context 重定向后计数停止、恢复后正常。
