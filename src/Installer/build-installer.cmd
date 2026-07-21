@echo off
rem Compiles FortiVpnSetup.exe. The .rc pulls build\payload.zip in as a resource, so
rem installer.ps1 has to have put it there first -- run that rather than this.
rem
rem Same story as build-native.cmd: cl.exe and rc.exe only exist inside a session that has
rem sourced vcvars64.bat, and the edition in its path is not fixed. vswhere is the
rem supported way to ask; the hardcoded path stays as a fallback.

setlocal
set vcvars=
set vswhere=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if exist "%vswhere%" (
    for /f "usebackq tokens=*" %%i in (`"%vswhere%" -latest -products * ^
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ^
        -property installationPath`) do set "vcvars=%%i\VC\Auxiliary\Build\vcvars64.bat"
)
if not defined vcvars set "vcvars=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%vcvars%" (
    echo Could not find vcvars64.bat. Install the "Desktop development with C++" workload.
    exit /b 1
)

call "%vcvars%" >nul
if errorlevel 1 exit /b 1

set here=%~dp0
if not exist "%here%build\payload.zip" (
    echo build\payload.zip is missing. Run installer.ps1, which creates it.
    exit /b 1
)
pushd "%here%build"

rc /nologo /fo FortiVpnSetup.res "%here%FortiVpnSetup.rc"
if errorlevel 1 (popd & exit /b 1)

rem /MT, not /MD: an installer that first needs the VC++ redistributable installed is no
rem use to somebody without an administrator. The cppwinrt headers next door are the same
rem ones the host builds against.
rem /DUNICODE: without it MAKEINTRESOURCE -- and so RT_RCDATA -- resolves to the ANSI
rem form, which FindResourceW will not take.
cl /nologo /std:c++20 /EHsc /permissive- /W3 /O2 /MT /DUNICODE /D_UNICODE ^
   /I "%here%..\Native\generated" ^
   "%here%FortiVpnSetup.cpp" FortiVpnSetup.res ^
   /Fe:FortiVpnSetup.exe ^
   /link windowsapp.lib

set rc=%errorlevel%
popd
exit /b %rc%
