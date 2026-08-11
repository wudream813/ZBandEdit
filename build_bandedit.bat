@echo off
rem ============================================================================
rem BandEdit 单文件构建: payload DLL -^> bin2c 生成内嵌头 -^> client 内嵌编译
rem 支持: MSVC(cl) 或 MinGW(g++/x86_64-w64-mingw32-g++)
rem ============================================================================
setlocal

where x86_64-w64-mingw32-g++ >nul 2>nul && ( set "CXX=x86_64-w64-mingw32-g++" & goto :mingw )
where g++ >nul 2>nul && ( set "CXX=g++" & goto :mingw )
where cl >nul 2>nul && goto :msvc
echo [x] 未找到编译器（需要 cl 或 g++/x86_64-w64-mingw32-g++）
exit /b 1

:mingw
echo [1/3] payload DLL...
echo   (payload: CRT-free, -nostdlib)
%CXX% -std=c++17 -O2 -shared -nostdlib -fno-exceptions -fno-rtti -fno-stack-protector -fno-stack-check -fno-builtin -Wl,-e,DllMain -o bandedit-payload-x64.dll bandpayload.cpp -lkernel32 -luser32 || exit /b 1
echo [2/3] bin2c -^> payload_bin.h...
%CXX% -std=c++17 -O2 -o bin2c.exe bin2c.cpp || exit /b 1
bin2c.exe bandedit-payload-x64.dll payload_bin.h kEmbeddedPayload || exit /b 1
echo [3/3] client（内嵌 payload）...
%CXX% -std=c++17 -O2 -Wall -Wextra -municode -o bandedit-x64.exe bandedit.cpp -static || exit /b 1
echo.
echo [√] 完成 -^> bandedit-x64.exe （单文件，无需附带 DLL）
exit /b 0

:msvc
echo [1/3] payload DLL...
cl /nologo /std:c++17 /W4 /utf-8 /LD bandpayload.cpp /Fe:bandedit-payload-x64.dll || exit /b 1
echo [2/3] bin2c -^> payload_bin.h...
cl /nologo /std:c++17 /W4 /utf-8 /EHsc bin2c.cpp /Fe:bin2c.exe || exit /b 1
bin2c.exe bandedit-payload-x64.dll payload_bin.h kEmbeddedPayload || exit /b 1
echo [3/3] client（内嵌 payload）...
cl /nologo /std:c++17 /W4 /utf-8 /EHsc bandedit.cpp /Fe:bandedit-x64.exe || exit /b 1
echo.
echo [√] 完成 -^> bandedit-x64.exe （单文件，无需附带 DLL）
exit /b 0
