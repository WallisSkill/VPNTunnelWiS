@echo off
rem Builds the native WinRT probe DLL.
rem
rem cl.exe is not on PATH and never will be: vcvars64.bat is what puts the compiler,
rem the CRT headers and the SDK libs there, so everything has to run inside one cmd
rem session that has sourced it.

setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1

set here=%~dp0
if not exist "%here%build" mkdir "%here%build"
pushd "%here%build"

rem windowsapp.lib is the umbrella import library for the WinRT API surface; without it
rem the RoGetActivationFactory / WindowsCreateString calls that winrt/base.h emits do
rem not link. The two exports are what makes the DLL an in-process WinRT server.
cl /nologo /std:c++20 /EHsc /permissive- /W3 /O2 /MD /LD ^
   /I "%here%generated" ^
   "%here%FortiPluginProbe.cpp" ^
   /Fe:FortiVpnNative.dll ^
   /link windowsapp.lib ^
   /EXPORT:DllGetActivationFactory /EXPORT:DllCanUnloadNow

if errorlevel 1 (popd & exit /b 1)

rem The host executable. /APPCONTAINER is not decoration: the app model refuses to launch
rem a packaged app whose image is not marked for an app container, which is what killed
rem the .NET console host with "the app didn't start". /SUBSYSTEM:WINDOWS goes with
rem wWinMain and keeps a console from appearing.
cl /nologo /std:c++20 /EHsc /permissive- /W3 /O2 /MD ^
   /I "%here%generated" ^
   "%here%FortiVpnHostUwp.cpp" ^
   /Fe:FortiVpnHost.exe ^
   /link windowsapp.lib ^
   /SUBSYSTEM:WINDOWS /APPCONTAINER

if errorlevel 1 (popd & exit /b 1)

rem The forwarding server. No cppwinrt headers here on purpose -- it is plain Win32 plus
rem one WinRT string call, so nothing it does can itself fail to initialise.
cl /nologo /std:c++20 /EHsc /permissive- /W3 /O2 /MD /LD ^
   "%here%FortiVpnShim.cpp" ^
   /Fe:FortiVpnShim.dll ^
   /link windowsapp.lib ^
   /EXPORT:DllGetActivationFactory /EXPORT:DllCanUnloadNow

set rc=%errorlevel%
popd
exit /b %rc%
