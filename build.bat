@echo off
rem ============================================================
rem  PEHookFramework build script (requires Visual Studio 2019+)
rem  Usage: build.bat [x64|x86]    default: x64
rem  Change VS path below if your VS is installed elsewhere.
rem ============================================================
setlocal
set ARCH=%1
if "%ARCH%"=="" set ARCH=x64
set "VS=D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise"

if "%ARCH%"=="x64" (
  call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul
) else (
  call "%VS%\VC\Auxiliary\Build\vcvars32.bat" >nul
)
if errorlevel 1 (
  echo [ERROR] vcvars init failed, check VS install path
  exit /b 1
)

set "ROOT=%~dp0"
set "SRC=%ROOT%src"
set "HDE=%ROOT%hde"
set "OUT=%ROOT%bin\%ARCH%"
if not exist "%OUT%" mkdir "%OUT%"

echo === [1/3] PEHookInjector.exe ===
cl /nologo /W3 /O2 /MT /EHsc /utf-8 /D_CRT_SECURE_NO_WARNINGS /I "%SRC%" /I "%HDE%" ^
   "%SRC%\main.cpp" "%SRC%\reflective.cpp" "%SRC%\inject.cpp" ^
   "%SRC%\iathook.cpp" "%SRC%\inlinehook.cpp" "%SRC%\vthook.cpp" "%SRC%\contexthook.cpp" ^
   "%HDE%\hde32.c" "%HDE%\hde64.c" ^
   /Fe:"%OUT%\PEHookInjector.exe" /link user32.lib kernel32.lib advapi32.lib
if errorlevel 1 goto :err

echo === [2/3] PEHookDemo.dll ===
cl /nologo /W3 /O2 /MT /EHsc /utf-8 /LD /D_CRT_SECURE_NO_WARNINGS /I "%SRC%" ^
   "%SRC%\hook_demo.cpp" ^
   /Fe:"%OUT%\PEHookDemo.dll" /link user32.lib kernel32.lib
if errorlevel 1 goto :err

echo === [3/3] PEHookLoaderStub.dll ===
cl /nologo /W3 /O2 /MT /EHsc /utf-8 /LD /D_CRT_SECURE_NO_WARNINGS /I "%SRC%" ^
   "%SRC%\loader_stub.cpp" "%SRC%\reflective.cpp" ^
   /Fe:"%OUT%\PEHookLoaderStub.dll" /link kernel32.lib
if errorlevel 1 goto :err

echo.
echo [OK] Build done: %OUT%
echo      PEHookInjector.exe  PEHookDemo.dll  PEHookLoaderStub.dll
goto :eof

:err
echo [ERROR] Build failed
exit /b 1
endlocal
