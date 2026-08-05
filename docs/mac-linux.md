# Mac and Linux (`fortivpn`)

The Windows plugin cannot run on macOS or Linux — its whole delivery mechanism is the
Windows VPN Platform. So `src/Cli` is a **separate, self-written client** for those systems
that speaks the same protocol. It is not a wrapper around another tool: it reuses this
repo's own SSL-VPN core — the exact frame format (`Ppp.cs`) and second-factor logic
(`TwoFactor.cs`) the plugin proved against this gateway are linked in unchanged — and adds
the two pieces the plugin never needed because Windows owned the interface:

- a **`SslStream`** transport in place of the Windows-only WinRT socket, and
- a **tun/utun data plane**: it opens the interface itself (`/dev/net/tun` on Linux, a
  `utun` kernel-control socket on macOS) and pumps IP packets between it and the tunnel.

One thing the plugin has that this cannot: the "no administrator" property is specific to
the Windows VPN Platform. Opening a tunnel interface and changing routes needs root here,
so `fortivpn` runs under **sudo**. There is no unprivileged path on macOS/Linux.

Scope is **SSL-VPN only** — the same protocol the gateway already serves. There is no
IPsec/IKE here (openfortivpn has none either; IKE is a different stack entirely).

## Build

Needs the .NET 9 SDK. A single self-contained binary, no runtime to install on the target:

    # Linux x64
    dotnet publish src/Cli -c Release -r linux-x64   --self-contained -p:PublishSingleFile=true -o out/cli-linux-x64
    # Linux arm64
    dotnet publish src/Cli -c Release -r linux-arm64 --self-contained -p:PublishSingleFile=true -o out/cli-linux-arm64
    # macOS Apple Silicon
    dotnet publish src/Cli -c Release -r osx-arm64   --self-contained -p:PublishSingleFile=true -o out/cli-osx-arm64
    # macOS Intel
    dotnet publish src/Cli -c Release -r osx-x64     --self-contained -p:PublishSingleFile=true -o out/cli-osx-x64

The result is `out/cli-<rid>/fortivpn`. Copy that one file to the target machine.

## Use

    sudo ./fortivpn vpn.example.com:<port>

Use the **same host and port you type in the Windows profile** (`https://vpn.example.com:<port>`).
It prompts for the account name (unless `-u`), the password, and — when the account has a
second factor — the FortiToken code. On success it brings up the interface, installs the
routes the gateway pushes, and runs until you press **Ctrl-C**, which tears the interface,
routes and DNS back down and logs the session out cleanly.

    OPTIONS
      -u, --user <name>        account name (prompted if omitted)
      --password-stdin         read the password from stdin (for automation)
      --otp <code>             pass the second-factor code non-interactively
      --trusted-cert <sha256>  pin the gateway certificate; refuse any other
      --full                   force a full tunnel even if the portal pushes split routes
      -v, --verbose            print the protocol trace

### Certificate

The FortiGate presents its own appliance certificate, which chains to nothing a machine
trusts — FortiClient and openfortivpn accept it the same way. On the first connection
`fortivpn` prints the certificate's SHA-256 fingerprint. Verify it is the gateway's, then
pin it so nothing else is ever accepted:

    sudo ./fortivpn vpn.example.com:<port> --trusted-cert <the-64-hex-fingerprint>

### Second factor without a prompt

    echo 'password' | sudo ./fortivpn vpn.example.com:<port> -u alice --password-stdin --otp 123456

### Routing

The **gateway** decides what is routed, exactly as on Windows:

- If the portal is split-tunnel, only the office networks it pushes go through the tunnel;
  the rest of your traffic stays on your normal interface. This is the default.
- If the portal pushes nothing (full access), `fortivpn` takes the default route via the
  `0.0.0.0/1` + `128.0.0.0/1` pair and pins the gateway to your real uplink so the encrypted
  tunnel does not recurse into itself. Force this with `--full`.

### DNS

On Linux `fortivpn` rewrites `/etc/resolv.conf` with the pushed servers and restores it on
exit; a box running `systemd-resolved`/`resolvconf` may reassert its own, in which case set
DNS through that. On macOS DNS is not changed automatically — if office names do not resolve,
`sudo networksetup -setdnsservers Wi-Fi <server> ...` and clear it with `... Wi-Fi empty`.

## The desktop VPN panel

Both systems have a built-in VPN page, like Windows' Settings > Network & internet > VPN.
How far a FortiGate SSL-VPN can be pushed into them differs sharply.

### Ubuntu / GNOME — yes, through NetworkManager

The VPN section of GNOME Settings is **NetworkManager**, and NetworkManager takes VPN
plugins the way Windows takes a VPN provider. Debian and Ubuntu already ship one for this
protocol, wrapping openfortivpn:

    sudo apt install network-manager-fortisslvpn-gnome

Then **Settings > Network > VPN > +** offers "Fortinet SSLVPN". Fill in the gateway
(`vpn.example.com`, and the port your Windows profile uses) and your account name.

Two things this buys that the CLI cannot:

- The connection is dialled from the desktop, including the top-bar switch.
- **No `sudo` per connection.** Installing needs root once; after that the NetworkManager
  daemon (already root) does the work and polkit authorises your desktop user. This is the
  closest thing on Linux to the Windows plugin's no-administrator property.

**Check the second factor before relying on it.** The stock plugin's handling of FortiToken
/ OTP accounts has historically been the weak spot, and this gateway's accounts use one. If
the GUI cannot complete a `ret=2` challenge, `fortivpn` above still signs in — and the
fallback is a NetworkManager plugin of our own wrapping this client, which reuses the exact
2FA code the Windows plugin already proves against this gateway. Not written yet: it is
worth knowing whether the stock one suffices first.

### macOS — possible, but behind Apple's paywall

macOS's built-in VPN types (IKEv2, L2TP/IPsec) are the native IKE stack and cannot carry
this protocol, so there is no shortcut through them. Appearing in **System Settings > VPN**
means shipping an app with a **`NEPacketTunnelProvider`** — the direct analogue of the
Windows `IVpnPlugIn`. What that costs, against Windows:

| | Windows plugin | macOS NEPacketTunnelProvider |
| --- | --- | --- |
| Developer account | free (Developer Mode) | Apple Developer Program, paid yearly |
| Privileged entitlement | granted by Developer Mode | `com.apple.developer.networking.networkextension`, granted by Apple on request |
| Signing / notarisation | not required | required |
| Language | reuses this repo's C# | Swift/Obj-C; NetworkExtension has no .NET binding |

So on macOS the CLI above is the practical answer unless someone is willing to pay for and
maintain a signed app.

## Notes

- The CLI needs `sudo`; there is no unprivileged mode on macOS/Linux. The NetworkManager
  route above is the exception, and only on Linux.
- The 2FA handling is the gateway's, identical to what the Windows plugin drives — the code
  the token app shows is what you enter here too.
- One protocol core, two front ends: a bug fixed in `Ppp.cs`/`TwoFactor.cs` is fixed for both
  Windows and macOS/Linux at once.
