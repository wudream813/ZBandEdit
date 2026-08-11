@echo off
rem ============================================================
rem  bandhook 构建脚本 (MSVC 或 MinGW)
rem    MSVC(x64 Native Tools 命令行):  build_hook.bat
rem    MinGW:                          build_hook.bat mingw
rem ============================================================
if /i "%1"=="mingw" (
    g++ -std=c++17 -O2 -Wall -Wextra -shared -o bandpayload-x64.dll bandpayload.cpp -static
    g++ -std=c++17 -O2 -Wall -Wextra -municode -o bandclient-x64.exe bandclient.cpp -static
    goto :done
)
cl /std:c++17 /W4 /utf-8 /LD /nologo bandpayload.cpp /link /OUT:bandpayload-x64.dll
cl /std:c++17 /W4 /utf-8 /nologo bandclient.cpp
:done
echo.
echo 使用 (两个二进制需在同一目录):
echo   bandclient-x64.exe me 16        ^<-^> 创建测试窗口送入 ZBID_SYSTEM_TOOLS
echo   bandclient-x64.exe me 16 --manual  ^<-^> 手动按 Win/Win+Tab 触发
echo   bandclient-x64.exe --unload     ^<-^> 卸载 explorer 内的 hook
