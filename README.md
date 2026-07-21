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

## Build and install

    powershell -ExecutionPolicy Bypass -File build.ps1     # produces dist\
    powershell -ExecutionPolicy Bypass -File install.ps1   # registers the provider
    powershell -ExecutionPolicy Bypass -File uninstall.ps1
    powershell -ExecutionPolicy Bypass -File package.ps1   # out\FortiVpnPlugin-<ver>.zip

One requirement: **Developer Mode** on (Settings > System > For developers). Windows
only registers an unsigned package with it enabled. .NET does not have to be installed
— the runtime ships inside `dist\`.

`install.ps1` creates no connection; it only registers the provider. Add the connection
yourself in Settings, choosing "FortiGate SSL-VPN" as the VPN provider and entering your
gateway address including the port.

## Documentation

- [docs/readme-package.md](docs/readme-package.md) — what ships in the zip, for whoever installs it.
- [docs/status.md](docs/status.md) — what works, and the notes behind every fix: why the host
  must be native, why the deferral has to rotate, what the Fortinet frame looks like.
