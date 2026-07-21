# FortiGate SSL-VPN for the built-in Windows VPN client

This package adds a **VPN provider** named "FortiGate SSL-VPN" to Settings > Network &
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

## Creating a connection

1. Settings > Network & internet > VPN > **Add VPN**
2. VPN provider: **FortiGate SSL-VPN**
3. Connection name: anything you like
4. Server name or address: the gateway address including the port, e.g. `vpn.example.com:8080`
5. Save, then click **Connect** and enter your own account

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
