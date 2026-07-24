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
VPN > Add VPN, choosing "VPNTunnelWiS" as the VPN provider and entering your gateway
as a full URL with the port — `https://vpn.example.com:8080`. The `https://` matters:
Settings takes a bare `host:port` happily, but no plugin can read that form back.

### Split tunnel

By default the whole machine's traffic goes through the tunnel, so while the VPN is up
the machine uses the gateway for everything — which is what you want if the point is to
be *on* the office network, but it means the rest of the internet rides through the
gateway too (and is lost entirely if the gateway does not route it out).

Add **`/split`** to the end of the address to route only private networks through the
tunnel and leave the public internet on your normal adapter:

    https://vpn.example.com:8080/split

That tunnels `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16` — enough to remote-desktop
into office machines while everything else stays direct. To tunnel exact networks instead,
name them (comma-separated; a bare address means a single host):

    https://vpn.example.com:8080/split=10.1.0.0/16,192.168.50.0/24

Your own local subnet is always kept off the tunnel, so local devices keep working even
when it overlaps one of the ranges above.

#### Locking split behind a key

Split can be gated so it only turns on for someone who knows a secret you choose. Set
`SplitUnlockKey` in [`src/Plugin/FortiPlugin.cs`](src/Plugin/FortiPlugin.cs) before you
build. Then, whenever a connection whose address ends in `/split` comes up, a code box
appears and the split routes are only applied if what you type matches the key — a wrong
key, or a cancelled prompt, leaves the connection on a full tunnel. Nothing is stored in
the address, so the key never travels in the profile. Leave `SplitUnlockKey` empty to keep
`/split` working with no prompt.

### Two-factor (FortiToken / OTP)

No setup needed. If the gateway answers sign-in with a second-factor challenge, Windows
puts up a code box; enter the FortiToken / one-time code and the sign-in completes.

When an account needs a gateway 2FA code **and** the split key, both boxes appear in turn:
the gateway's code first, then the split key. Same-looking dialogs — the order is what
tells them apart.

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
