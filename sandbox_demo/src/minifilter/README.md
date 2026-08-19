# M9 Minifilter — 构建与运行说明

本目录是 M9 内核 Minifilter 驱动（形态 A+B：审计 + 拦截 + 用户态下发策略）。
和前 8 个用户态 milestone 不同，`.sys` 驱动本体**必须用 WDK 单独编译**，不进主 CMake。

## 文件清单

| 文件 | 说明 | 编译方式 |
|---|---|---|
| `sandbox_minifilter.c` | 驱动本体（DriverEntry + PreCreate + 通信端口） | WDK |
| `mf_protocol.h` | 内核↔用户态共享协议头 | 两端共用 |
| `sandbox_minifilter.inf` | 安装信息（altitude=370000 / FSFilter） | 随驱动打包 |
| `sandbox_minifilter.vcxproj` | WDK 驱动工程 | 用 VS+WDK 打开编译 |
| `mf_ctl.cc` | 用户态控制程序 | 主 CMake（`mf_ctl` target） |

配套脚本（在项目根）：`install_mf.bat` / `run_mf.bat` / `uninstall_mf.bat`。

## 一、一次性环境准备（在 VM 里做！）

内核代码 bug = 蓝屏（BSOD）。**强烈建议在 VM 里跑并先打快照**。

```
:: 1) 开测试签名模式（否则未 EV 签名的 .sys 加载失败），然后重启
bcdedit /set testsigning on
shutdown /r /t 0
```

## 二、编译

```
:: 1) 驱动本体（需 WDK）：用 Visual Studio 打开 sandbox_minifilter.vcxproj
::    选 x64 / Debug，生成 -> 得到 sandbox_minifilter.sys
::    （命令行亦可：msbuild sandbox_minifilter.vcxproj /p:Configuration=Debug /p:Platform=x64）

:: 2) 用户态控制程序（普通 MSVC，主 CMake）：
cmake --build build_m0 --config Debug --target mf_ctl
```

### ✅ 本机实测：已成功编出 sandbox_minifilter.sys（2026-08-19，VS2022 Pro + WDK 10.0.26100）

命令行编译（用 VS 的 MSBuild）：
```
& 'C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe' ^
  sandbox_minifilter.vcxproj /p:Configuration=Debug /p:Platform=x64 ^
  /p:SpectreMitigation=false /p:EnableInf2cat=false /p:GenerateDriverPackage=false
```
产物：`src\minifilter\x64\Debug\sandbox_minifilter.sys`（约 8.7 KB）。

**编译时踩的三个坑（都是环境/打包问题，非代码问题）**：
1. **MSB8040 需要 Spectre 缓解库**：VS 没装 "Spectre-mitigated libs" 组件。解法：工程 Globals 段加 `<SpectreMitigation>false</SpectreMitigation>`（或命令行 `/p:SpectreMitigation=false`）。学习 demo 不需要 Spectre 库。
2. **InfVerif.dll 找不到 / inf2cat 退出 -2**：WDK 的 INF 校验和 .cat 生成步骤（缺 x86\InfVerif.dll + INF 缺 [SourceDisksFiles] 段）。解法：给 INF 补 `[SourceDisksNames]`/`[SourceDisksFiles]` 段，并关掉打包 `/p:EnableInf2cat=false /p:GenerateDriverPackage=false`。这两步只影响 .cat 签名产物，不影响 .sys。
3. **SignTool 缺 /fd**：编译后自动测试签名失败。解法：工程关掉自动签名（`SignMode=Off`）。加载到 VM 时用测试证书/testsigning 单独处理。

> 结论：**.sys 本体编译零 error**（仅几个无害 warning：C4819 源码 UTF-8 vs 代码页 936、C4100 未引用参数）。签名/打包留到 VM 加载阶段。

## 三、加载与运行

```
:: 1) 安装 + 加载驱动（管理员，脚本会自动提权）
install_mf.bat

:: 2) 起控制程序：下发黑名单 + 收审计（管理员）
run_mf.bat
::    默认把包含 "\sandbox_secret\" 的路径设为敏感黑名单

:: 3) 验证：另开一个窗口，用记事本/type 打开 C:\sandbox_secret\a.txt
::    - run_mf 窗口应打印 [audit] pid=... BLOCKED ... \SANDBOX_SECRET\A.TXT
::    - 记事本应报"拒绝访问"
::    同时随手打开别的文件，会看到 [audit] ... allow ... 的审计流

:: 4) 卸载
uninstall_mf.bat
```

## 四、验证驱动状态

```
fltmc filters          :: 应能看到 sandboxmf，altitude 370000
fltmc instances        :: 看挂载到哪些卷
```

## 五、常见坑

- **fltmc load 失败 0x801f0011 等**：testsigning 没开或没重启；或 .sys 没做测试签名。
- **加载后立即蓝屏**：多半是回调里 IRQL/内存问题——本 demo 的 PreCreate 在 PASSIVE_LEVEL、只读安全，若改动注意别在 DISPATCH_LEVEL 调分页 API。
- **mf_ctl 连端口失败**：驱动没加载，或没用管理员（端口 SD 只放行 Admin/SYSTEM）。
- **改完 .sys 重新加载**：必须先 `uninstall_mf.bat` 再 `install_mf.bat`（fltmc 不能热替换同名已加载驱动）。
- **别在主力机首跑**：VM + 快照，崩了回滚。
