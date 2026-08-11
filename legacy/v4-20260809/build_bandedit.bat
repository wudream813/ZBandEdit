@echo off
rem ============================================================
rem  BandEdit 构建脚本
rem    MSVC(x64 Native Tools 命令行):  build_bandedit.bat
rem    MinGW:                          build_bandedit.bat mingw
rem ============================================================
if /i "%1"=="mingw" (
    g++ -std=c++17 -O2 -Wall -Wextra -shared -o bandedit-payload-x64.dll bandpayload.cpp -static
    g++ -std=c++17 -O2 -Wall -Wextra -municode -o bandedit-x64.exe bandedit.cpp -static
    goto :done
)
cl /std:c++17 /W4 /utf-8 /LD /nologo bandpayload.cpp /link /OUT:bandedit-payload-x64.dll
cl /std:c++17 /W4 /utf-8 /nologo bandedit.cpp /link /OUT:bandedit-x64.exe
:done
echo.
echo 快速体验:
echo   bandedit-x64.exe pick           鼠标取窗 (F8 捕获)
echo   bandedit-x64.exe set me 16      测试窗口送入 ZBID_SYSTEM_TOOLS
echo   bandedit-x64.exe scan           查看 Band 地图
echo   bandedit-x64.exe unload         清理 explorer
