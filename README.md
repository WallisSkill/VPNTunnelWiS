# FortinetVpn

A **VPN provider** for the VPN page built into Windows. Install it and a FortiOS
SSL-VPN gateway becomes something you dial from Settings > Network & internet > VPN,
like any other connection. No FortiClient, and no administrator rights anywhere.

It is a UWP VPN Platform plugin (`IVpnPlugIn` + `IBackgroundTask`) in three layers:

    FortiVpnHost.exe    native UWP host, /SUBSYSTEM:WINDOWS /APPCONTAINER
      -> FortiVpnShim.dll     in-process WinRT server, starts CoreCLR via hostfxr
        -> FortiVpnPlugin.dll   the managed plugin

No gateway address is baked in. The plugin reads it from whatever profile Windows
dials, and the tools under `tools\` take it on the command line.

## Install

Download `FortiVpnSetup-<version>.exe` from the
[latest release](https://github.com/WallisSkill/FortinetVpn/releases) and run it. That is
the whole install — the layout rides inside the executable, so there is nothing to unpack
and nothing to download afterwards. Run it again with `/remove` to uninstall.

One requirement: **Developer Mode** on (Settings > System > For developers). Windows only
registers an unsigned package with it enabled, and turning it on does not need an
administrator either. .NET does not have to be installed — the runtime ships inside the
package.

Nothing creates a connection for you. Add it yourself in Settings > Network & internet >
VPN > Add VPN, choosing "FortiGate SSL-VPN" as the VPN provider and entering your gateway
address including the port.

## Build

    powershell -ExecutionPolicy Bypass -File build.ps1      # produces dist\
    powershell -ExecutionPolicy Bypass -File installer.ps1  # out\FortiVpnSetup-<ver>.exe
    powershell -ExecutionPolicy Bypass -File package.ps1    # out\FortiVpnPlugin-<ver>.zip

    powershell -ExecutionPolicy Bypass -File install.ps1    # register dist\ in place
    powershell -ExecutionPolicy Bypass -File uninstall.ps1

`install.ps1` registers the `dist\` folder where it stands, which is the short way round
while working on the plugin. `installer.ps1` is what produces the file other people get.

Needs the .NET 9 SDK, the C++ toolset ("Desktop development with C++"), and the Windows
SDK. The build is Windows-only and not by preference: `cl.exe`, `makepri` and a win-x64
self-contained publish leave no choice.

## Documentation

- [docs/readme-package.md](docs/readme-package.md) — what ships in the zip, for whoever installs it.
- [docs/status.md](docs/status.md) — what works, and the notes behind every fix: why the host
  must be native, why the deferral has to rotate, what the Fortinet frame looks like.
