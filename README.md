# ZBandEdit (BandEdit) —— Windows 窗口 Z-Band 一体化编辑工具

> ⚠️ **安全声明：仅供自己机器上的学习/逆向研究使用。**
> `set` 子命令会向 `explorer.exe` 注入代码（手动映射、不落盘）。注入是 AV/EDR 的重点
> 监控行为，被拦截属正常现象；请仅在**自己的机器**上实验。清场方式：
> `bandedit-x64 unload`，或直接重启资源管理器。**x64 only（在 Win11 24H2 验证）。**

一个 exe 打通「找窗口 → 查 Band → 改 Band」：

```
bandedit-x64                            只装载 hook（注入 payload 到 explorer，不做层级操作）
bandedit-x64 scan [--all]               按 Z-Band 分组绘制桌面"层级地图"
bandedit-x64 list [子串]                按 Z 序平铺列出顶层窗口（含 hwnd）
bandedit-x64 pick                       鼠标取窗：悬停实时预览, F8 捕获, Esc 退出
bandedit-x64 band <hwnd|pick>           查询窗口 Z-Band（标题/类名/进程/位置）
bandedit-x64 set <hwnd|pick|me> <zbid>  把窗口改到指定 ZBID(0~18)，默认 direct 直调
bandedit-x64 top|bottom|topmost|notopmost <hwnd|pick>   Band 内 Z 序微调
bandedit-x64 unload                     卸载 explorer 内的 hook 与 payload（自我释放）
```

全局开关：`--debug`（铺"黑匣子"崩溃记录页 + 遥测输出）、`--trampoline`（回退蹦床模式）、
`--induce`（direct 的下下策：允许焦点诱导取 key）。

## 它能干什么

把**任意**窗口扔进任意 Z-Band。比如把计算器送进 `ZBID_SYSTEM_TOOLS(16)`（任务管理器同款
置顶层）、把窗口压进桌面层之下等。全程**零按键、零焦点切换、无窗口闪烁**：

```
bandedit-x64 set pick 16     ← 鼠标点到计算器，按 F8，完成。毫秒级。
```

## Z-Band 速查表（Win11 24H2 实测）

| ZBID | 名称 | 谁住在里面 |
|---|---|---|
| 0 | ZBID_DEFAULT | （保留） |
| 1 | ZBID_DESKTOP | 所有普通应用窗口 |
| 2 | ZBID_UIACCESS | UIAccess 程序（你的计算器默认就在这层） |
| 6 | ZBID_MOGO | 开始菜单等 shell 浮层 |
| 14 | ZBID_GENUINE_WINDOWS | 正版验证提示层 |
| 16 | ZBID_SYSTEM_TOOLS | 任务管理器"总在前面"层 |
| 17 | ZBID_LOCK | 锁屏层 |
| 18 | ZBID_ABOVELOCK_UX | 锁屏之上的 UX 层 |

## 工作原理（v6.x 架构）

1. **手动映射注入**：客户端把内嵌的 payload（CRT-free、无 .reloc、无 TLS、仅导入
   kernel32/user32）在 explorer 地址空间内手工展开成可执行映像——**不落盘、不进模块
   链表**，模块枚举不可见；
2. **IAT Hook**：hook `user32!SetWindowBand` 与 `user32` 序数 **#2510**
   （`NtUserEnableIAMAccess` 的 user32 存根）；
3. **静默 IAM 钥匙**：在 explorer 可写内存里扫描候选 QWORD，用 #2510 做"预言机"逐个验证
   （错误 key 只会返回 err=87、无副作用）。只有桌面线程能 `NtUserAcquireIAMKey`，
   所以我们直接向桌面线程借——key 命中后缓存，后续 set 毫秒级完成；
4. **direct 直调**：共享内存块派单给 payload 常驻执行线程，
   `EnableIAM(TRUE) → SetWindowBand → EnableIAM(FALSE)` 原样执行并回读验证。

## 已知特性（不是 bug）

- **Band > ZBID_DESKTOP 的窗口会被内核强制追加 `WS_EX_TOPMOST`**：这是 Band 机制的
  内核侧外观徽标，用任何公开 API 都撕不掉（社区有同样记载）；仅当目标 Band ≤ 1 时
  payload 才会尝试回滚顺带设置。它不影响窗口的焦点/输入行为。

## 构建

```
build_bandedit.bat        ← 一条命令：payload → bin2c → 单文件 exe（MSVC 或 MinGW 皆可）
```

产物：`bandedit-x64.exe`（**单文件**，payload 已内嵌，分发只需这一个 exe）。
CI/沙箱验证构建使用 MinGW：
`x86_64-w64-mingw32-g++ -O2 -municode -static`（payload 额外 `-nostdlib -fno-exceptions …`）。

## 版本沿革

- **v6.2**（当前 · 2026-08-11）✅ 外来窗口 direct 直调稳定可用；修复跨 v5.x~v6.1 的
  **"假超时"**：取窗 F8 经 `GetAsyncKeyState` 轮询不消费控制台输入缓冲，残留按键被等待
  循环的 `_kbhit()` 取消判定瞬间捕获 → 报超时，但 payload 实际早已完工。
  （这个故事详见 `legacy/v4-20260809` 之上的完整折腾史：VEH 白名单、命名对象句柄续命、
  常驻执行线程、死亡笔记/TID 探针…… 最后发现凶手是客户端自己。）
- **v6.1** payload：免 `--debug` 法医字段（死亡笔记/线程 TID/主循环圈数），手动映射。
- **v4（2026-08-09，见 legacy/）**：蹦床模式时代的稳定版，全部功能实测通过。

## 仓库布局

```
bandedit.cpp         客户端（单文件工具本体，内嵌 payload）
bandpayload.cpp      payload（CRT-free，手动映射专用）
bin2c.cpp            payload → 内嵌头 payload_bin.h 生成器
build_bandedit.bat   一键构建
legacy/v4-20260809/  历史稳定版完整存档（源码 + 二进制 + 说明）
```

## License

MIT — 详见 [LICENSE](LICENSE)。
