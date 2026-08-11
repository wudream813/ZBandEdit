# BandEdit —— 窗口 Z-Band 一体化编辑工具

> ⚠️ **仅供自己机器学习/逆向研究使用。** `set` 子命令通过 DLL 注入 explorer.exe 实现：
> 被杀毒软件拦截属正常现象（注入是 AV 重点监控行为），写错代码可能导致 shell 崩溃重启。
> x64 only。

把「找窗口 → 查 Band → 改 Band」集成进一个 exe：

```
bandedit scan [--all]                 按 Z-Band 分组绘制桌面"层级地图"
bandedit list [子串]                  按 Z 序平铺列出顶层窗口（含 hwnd）
bandedit pick                         鼠标取窗：悬停实时预览, F8 捕获, Esc 退出
bandedit band <hwnd|pick>             查询窗口 Z-Band（标题/类名/进程/位置）
bandedit set <hwnd|pick|me> <zbid> [--manual] [--direct] [--dll 路径]
                                      直接把窗口改到指定 ZBID(0~18)
bandedit top|bottom|topmost|notopmost <hwnd|pick>   Band 内 Z 序微调
bandedit unload                       卸载 explorer 内的 hook 与 payload DLL
```

目标窗口三种指定方式：

| 写法 | 说明 |
|---|---|
| `bandedit set 0x30B1E 16` | 直接给 HWND（scan/list 里复制） |
| `bandedit set pick 16` | 鼠标点选：悬停预览 → F8 捕获 → 自动进入修改流程 |
| `bandedit set me 16` | 自动创建测试窗口做实验（最推荐首次体验） |

## 文件

| 文件 | 说明 |
|---|---|
| `bandedit-x64.exe` | 主程序（客户端 + 注入器 + 查询/取窗） |
| `bandedit-payload-x64.dll` | explorer 载荷（需与 exe 同目录；兼容旧名 bandpayload-x64.dll） |
| `bandedit.cpp` / `bandpayload.cpp` | 全部源码 |
| `build_bandedit.bat` | Windows 下构建（MSVC / MinGW） |

## v2 新增：`--direct` 直调模式（免按键、可复用）

默认蹦床模式每次都要"触发一次 explorer 调用"。`--direct` 更进一步：

```
bandedit set me 16 --direct
```

1. payload 注入时在 `win32u!NtUserEnableIAMAccess` 上额外挂**嗅探 hook**（永远放行，只记参数）
2. 首次 --direct 请求时若还没有 key → 客户端按一次 Win → explorer 的 shell 线程调用
   `NtUserEnableIAMAccess(iamKey, TRUE)` → key 被捕获并**缓存在 payload 内存**
3. payload 的工作线程立刻自己调用 `NtUserEnableIAMAccess(key, TRUE)`（IAM 访问权**按线程生效**），
   然后**同线程直接 `SetWindowBand`** —— 不劫持、不影响 explorer 的任何调用
4. 此后所有 `--direct` 请求：**零触发、毫秒级**完成，直到 explorer 重启

> 原理来源：ADeltaX《How to call SetWindowBand》——IAM key 只能由桌面线程
> （SetShellWindow 调用者，即 explorer）通过 `NtUserAcquireIAMKey` 获取一次，
> 注入进程无法再申请，因此只能"钩出来"。key 全程不离开 explorer 进程内存。
>
> 若抓 key 超时（某些版本 explorer 触发路径不同）会提示换触发方式或回退蹦床模式；
> 蹦床模式运行时顺手也能抓到 key，之后再 `--direct` 即为纯直调。

## 原理（set 为什么能成）

Windows 8+ 的 Z-Band 在内核侧有 ACL 式检查：调用 `SetWindowBand` 的进程必须持有
**IAM 访问密钥**（`NtUserEnableIAMAccess`），而密钥在系统启动时被 **explorer.exe
独占**。所以 BandEdit 采用"蹦床"方案：

1. 把 payload DLL 注入 explorer.exe，在 `user32!SetWindowBand` 入口做 inline hook
2. 客户端通过共享内存 `Local\ZBandHookShareV1` 下发 `(hwnd, ZBID)` 请求
3. 按 Win 键 → explorer 打开开始菜单、自然调用 `SetWindowBand(任务栏,…,6)`
4. payload 仅此一次把参数替换为我们的请求 → 恢复原字节 → 以 explorer 身份执行
   → 权限通过 → 装回 hook。随后 shell 自身的调用全部正常放行。

详见源码注释与《Windows窗口层级探究.md》第 3 章。

## 推荐体验流程

```bat
bandedit scan                    :: 先看一眼当前 Band 地图
bandedit pick                    :: 熟悉鼠标取窗（Esc 退出）
bandedit set me 16               :: 测试窗口 → ZBID_SYSTEM_TOOLS
bandedit scan                    :: 再看：Band 16 分组里出现了你的测试窗口
bandedit set pick 2              :: 挑一个窗口送进 UIACCESS 层（应被 explorer 拒绝? 看结果）
bandedit unload                  :: 清理
```

玩"盖过任务管理器"：任务管理器 → 选项 → 置于顶层；然后 `bandedit set me 16`，
拖动测试窗口到任务管理器上方——普通 `WS_EX_TOPMOST` 做不到的事，Band 做到。

## 故障排查

- **远程 LoadLibraryW 返回 NULL**：payload DLL 不在同目录/被改名/被 AV 清掉；
  工具会逐个列出尝试过的路径与原因；也可用 `--dll "完整路径"` 显式指定。
  浏览器下载的文件建议右键 → 属性 → 解除锁定。
- **超时未触发**：Win11 上开始菜单改由 StartMenuExperienceHost 负责，
  用 `--manual` 手动按 Win / Win+Tab / 切换任务栏自动隐藏 尝试触发。
- **explorer 是 ARM64**：需要 ARM64 工具链重编 payload。

## 参考

- ADeltaX, *Window z-order in Windows 10* — https://blog.adeltax.com/window-z-order-in-windows-10/
- xmc0211/WindowTopMost — https://github.com/xmc0211/WindowTopMost/
