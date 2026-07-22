# VPNTunnelWiS for the built-in Windows VPN client

This package adds a **VPN provider** named "VPNTunnelWiS" to Settings > Network &
internet > VPN. Once it is installed you create a connection of your own pointing at
your own gateway. No FortiClient, no administrator rights.

## Requirements

One thing only: **Developer Mode** must be on.

    Settings > System > For developers > Developer Mode = On

Windows only registers an unsigned package when Developer Mode is on. .NET does not have
to be installed: the runtime ships inside `dist\`.

Windows 10 2004 or later, x64.

## Install

Unpack, then run this from the folder you unpacked into:

    powershell -ExecutionPolicy Bypass -File install.ps1

The script creates no connection. It only registers the provider.

There is also a single `FortiVpnSetup-<version>.exe` on the release page that does all of
the above by itself — no unpacking and no PowerShell. Run it with `/remove` to uninstall.
This zip exists for anyone who would rather see the scripts before running them.

## Creating a connection

1. Settings > Network & internet > VPN > **Add VPN**
2. VPN provider: **VPNTunnelWiS**
3. Connection name: anything you like
4. Server name or address: the gateway as a **full URL with the port**, e.g.
   `https://vpn.example.com:8080`
5. Save, then click **Connect** and enter your own account

Write the `https://` — it is not decoration. Settings accepts a bare
`vpn.example.com:8080` without complaint, but a plugin cannot read that form back: Windows
hands the address over either as a `HostName`, which rejects the colon outright, or as a
URI, which reads the host name as a scheme. With the prefix it parses, and the connection
fails at Connect with "no usable gateway address" without it.

The password goes straight from Windows to the gateway. Nothing in this package stores it.

The gateway usually returns no DNS servers, so connect to internal machines by **IP
address** rather than by name.

## Uninstall

    powershell -ExecutionPolicy Bypass -File uninstall.ps1

Connections you created are left alone. Add `-RemoveProfiles` to delete those as well.

## When it will not connect

The logs are in:

    %LOCALAPPDATA%\Packages\FortiGateSslVpn.Plugin_ze06k0zwcba52\AC\Temp\

`forti-plugin.log` is the one to read first: it records the address dialled, the TLS
handshake, and the reason a dial was refused.
