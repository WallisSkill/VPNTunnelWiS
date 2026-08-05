using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FortiVpn;

/// <summary>Bao gồm cấu hình gateway trả về khi tunnel đã lên. Same shape as the plugin's.</summary>
internal sealed class TunnelConfig
{
    public byte[] AssignedIp = new byte[4];
    public List<string> DnsServers = new();
    public List<string> DnsSuffixes = new();
    /// <summary>Split-tunnel destinations as (network, prefix length). Empty means full tunnel.</summary>
    public List<(string Network, int PrefixLength)> Routes = new();
    public uint Mtu = 1354;

    public string AssignedIpText => string.Join(".", AssignedIp);
}

/// <summary>
/// One FortiOS SSL-VPN session on macOS/Linux, from login through a negotiated PPP link,
/// after which <see cref="Stream"/> carries the raw FortiOS tunnel frames.
///
/// This is the portable twin of the Windows plugin's FortiSession: the handshake steps,
/// the cookie handling and the PPP negotiation are the same logic, but the transport is
/// a plain <see cref="SslStream"/> over a <see cref="TcpClient"/> instead of a WinRT
/// StreamSocket, and the tunnel stream is kept for the data plane rather than handed to
/// the OS VPN platform.
///
/// The whole conversation -- login, allocation, config, then the tunnel itself -- happens
/// on a single TLS connection, exactly as openfortivpn does it; a second socket for the
/// tunnel is what "Permission denied (5005)" means.
/// </summary>
internal sealed class FortiClient : IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly string? _pinSha256;   // lowercase hex, no separators; null = accept + report

    private TcpClient? _tcp;
    private SslStream? _ssl;

    private string _cookie = "";

    /// <summary>Bytes read past the end of the last HTTP response / PPP frame.</summary>
    private readonly List<byte> _spill = new();

    public TunnelConfig Config { get; } = new();
    public Action<string>? Log { get; set; }

    /// <summary>Called on a <c>ret=2</c> second-factor challenge. Argument is the gateway's
    /// message; return the code the user typed, or null to abandon sign-in.</summary>
    public Func<string, string?>? TwoFactorPrompt { get; set; }

    /// <summary>The live tunnel stream, valid once <see cref="ConnectAsync"/> returns.</summary>
    public SslStream Stream => _ssl ?? throw new InvalidOperationException("not connected");

    public string Cookie => _cookie;

    /// <summary>SHA-256 fingerprint of the certificate the gateway presented, lowercase hex.
    /// Printed so a first run can be pinned with <c>--trusted-cert</c>.</summary>
    public string? ServerCertSha256 { get; private set; }

    public FortiClient(string host, int port, string? pinSha256)
    {
        _host = host;
        _port = port;
        _pinSha256 = string.IsNullOrWhiteSpace(pinSha256)
            ? null
            : pinSha256.Replace(":", "").Replace(" ", "").Trim().ToLowerInvariant();
    }

    private void Trace(string message) => Log?.Invoke(message);

    public async Task ConnectAsync(string username, string password, CancellationToken ct = default)
    {
        _tcp = new TcpClient();
        await _tcp.ConnectAsync(_host, _port, ct);

        // A FortiGate presents its own appliance certificate, which chains to nothing a
        // machine trusts -- FortiClient and openfortivpn accept it the same way. We compute
        // and expose its SHA-256 so it can be pinned; when a pin was given we REQUIRE it,
        // otherwise we accept and report (like openfortivpn's first-run "trusted-cert" hint).
        _ssl = new SslStream(_tcp.GetStream(), leaveInnerStreamOpen: false, ValidateCert);
        await _ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = _host,
            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
                                  | System.Security.Authentication.SslProtocols.Tls13,
        }, ct);
        Trace($"TLS to {_host}:{_port}");

        await LoginAsync(username, password, ct);
        await RequestAllocationAsync(ct);
        await ReadTunnelConfigAsync(ct);
        await OpenTunnelAsync(ct);
        await NegotiatePppAsync(ct);
    }

    private bool ValidateCert(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        if (cert is null) return false;
        var sha = Convert.ToHexString(SHA256.HashData(cert.GetRawCertData())).ToLowerInvariant();
        ServerCertSha256 = sha;
        if (_pinSha256 is null)
        {
            // No pin: accept whatever the gateway presents (self-signed is expected) and let
            // the caller print the fingerprint so a careful user can pin it next time.
            return true;
        }
        if (sha == _pinSha256) return true;
        Trace($"certificate fingerprint {sha} does not match the pinned {_pinSha256}");
        return false;
    }

    // ---- transport helpers -------------------------------------------------

    private async Task WriteAsync(byte[] data, CancellationToken ct)
    {
        await _ssl!.WriteAsync(data, ct);
        await _ssl.FlushAsync(ct);
    }

    private readonly byte[] _readScratch = new byte[16384];

    private async Task<byte[]> ReadSomeAsync(CancellationToken ct)
    {
        var n = await _ssl!.ReadAsync(_readScratch, ct);
        if (n == 0) throw new InvalidOperationException("the gateway closed the connection");
        return _readScratch[..n];
    }

    /// <summary>Minimal HTTP/1.1 on the TLS stream. Returns headers and body separately and
    /// keeps whatever it over-read, because the same connection carries the next request.</summary>
    private async Task<(string Headers, string Body)> SendAsync(
        string method, string path, string? formBody, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.Append($"{method} {path} HTTP/1.1\r\n");
        sb.Append($"Host: {_host}:{_port}\r\n");
        sb.Append("User-Agent: Mozilla/5.0 SV1\r\n");
        sb.Append("Accept: */*\r\n");
        sb.Append("Connection: Keep-Alive\r\n");
        if (_cookie.Length > 0) sb.Append($"Cookie: SVPNCOOKIE={_cookie}\r\n");
        if (formBody is not null)
        {
            sb.Append("Content-Type: application/x-www-form-urlencoded\r\n");
            sb.Append($"Content-Length: {Encoding.ASCII.GetByteCount(formBody)}\r\n");
        }
        sb.Append("\r\n");
        if (formBody is not null) sb.Append(formBody);

        await WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), ct);

        var acc = new List<byte>(_spill);
        _spill.Clear();
        var headerEnd = -1;

        while (true)
        {
            var text = Encoding.ASCII.GetString(acc.ToArray());
            if (headerEnd < 0)
            {
                var i = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (i >= 0) headerEnd = i + 4;
            }
            if (headerEnd >= 0)
            {
                var hdr = text[..headerEnd];
                if (hdr.Contains("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase))
                {
                    if (text.IndexOf("\r\n0\r\n\r\n", headerEnd, StringComparison.Ordinal) >= 0)
                        return (hdr, text[headerEnd..]);
                }
                else
                {
                    var cl = Regex.Match(hdr, @"Content-Length:\s*(\d+)", RegexOptions.IgnoreCase);
                    var want = cl.Success ? int.Parse(cl.Groups[1].Value) : 0;
                    if (acc.Count - headerEnd >= want)
                    {
                        var bodyBytes = acc.Count - headerEnd;
                        if (bodyBytes > want) _spill.AddRange(acc.Skip(headerEnd + want));
                        return (hdr, text.Substring(headerEnd, want));
                    }
                }
            }

            acc.AddRange(await ReadSomeAsync(ct));
        }
    }

    private void TakeCookie(string headers)
    {
        foreach (Match m in Regex.Matches(headers,
                 @"Set-Cookie:\s*SVPNCOOKIE=([^;\r\n]*)([^\r\n]*)", RegexOptions.IgnoreCase))
        {
            // logincheck actively deletes SVPNCOOKIE (expiry in 1984) before the real one is
            // issued further along, so a deletion must not overwrite what we hold.
            var attrs = m.Groups[2].Value;
            if (attrs.Contains("1984") || attrs.Contains("1970")) continue;
            if (m.Groups[1].Value.Length == 0) continue;
            _cookie = m.Groups[1].Value;
        }
    }

    // ---- handshake steps ---------------------------------------------------

    private async Task LoginAsync(string username, string password, CancellationToken ct)
    {
        var (_, loginPage) = await SendAsync("GET", "/remote/login?lang=en", null, ct);

        string Hidden(string name)
        {
            var m = Regex.Match(loginPage,
                $@"name=""?{name}""?[^>]*value=""([^""]*)""", RegexOptions.IgnoreCase);
            if (!m.Success)
                m = Regex.Match(loginPage,
                    $@"value=""([^""]*)""[^>]*name=""?{name}""?", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value : "";
        }

        var form = $"ajax=1&username={Uri.EscapeDataString(username)}" +
                   $"&credential={Uri.EscapeDataString(password)}" +
                   $"&realm={Uri.EscapeDataString(Hidden("realm"))}" +
                   $"&magic={Uri.EscapeDataString(Hidden("magic"))}" +
                   $"&reqid={Uri.EscapeDataString(Hidden("reqid"))}" +
                   $"&grpid={Uri.EscapeDataString(Hidden("grpid"))}" +
                   $"&just_logged_in=1";

        var (loginHdr, loginBody) = await SendAsync("POST", "/remote/logincheck", form, ct);

        // ret=2 is a challenge, not a rejection: a second factor (FortiToken / OTP). The
        // parsing lives in the shared TwoFactor; here we only prompt and re-POST.
        if (TwoFactor.IsChallenge(loginBody))
        {
            var code = TwoFactorPrompt?.Invoke(TwoFactor.ChallengeMessage(loginBody));
            if (string.IsNullOrEmpty(code))
                throw new UnauthorizedAccessException(
                    "this account needs a verification code and none was entered");

            var otpForm = TwoFactor.BuildOtpForm(username, Hidden("realm"), loginBody, code);
            Trace("second factor requested; submitting the code");
            (loginHdr, loginBody) = await SendAsync("POST", "/remote/logincheck", otpForm, ct);
        }

        if (!loginBody.Contains("ret=1") && !loginBody.Contains("/sslvpn/portal.html"))
            throw new UnauthorizedAccessException(
                "sign-in failed (wrong user name, password, or verification code)");

        TakeCookie(loginHdr);

        // The usable SVPNCOOKIE is issued by the host-check step, not by logincheck. Take
        // everything after "redir=" to end of line: the value is itself a query string full
        // of '&', and stopping at the first one drops required parameters.
        var redir = Regex.Match(loginBody, @"redir=(\S+)");
        if (redir.Success)
        {
            var (hcHdr, _) = await SendAsync("GET", redir.Groups[1].Value.Trim(), null, ct);
            TakeCookie(hcHdr);
        }
        else
        {
            var (pHdr, _) = await SendAsync("GET", "/sslvpn/portal.html", null, ct);
            TakeCookie(pHdr);
        }

        if (_cookie.Length == 0) throw new UnauthorizedAccessException("no SVPNCOOKIE was issued");
        Trace($"sign-in OK (cookie len={_cookie.Length})");
    }

    private async Task RequestAllocationAsync(CancellationToken ct)
    {
        // Nobody reads these two bodies. The gateway will not hand out a tunnel until the
        // session has been allocated one; without them every tunnel request comes back
        // "Permission denied (5005)". /remote/index answering 403 is normal.
        await SendAsync("GET", "/remote/index", null, ct);
        await SendAsync("GET", "/remote/fortisslvpn", null, ct);
    }

    private async Task ReadTunnelConfigAsync(CancellationToken ct)
    {
        var (xmlHdr, xml) = await SendAsync("GET", "/remote/fortisslvpn_xml", null, ct);
        Trace($"fortisslvpn_xml: {xmlHdr.Split('\r')[0]} body={xml.Length}");

        var addr = Regex.Match(xml, @"<assigned-addr[^>]*ipv4=['""]([^'""]+)", RegexOptions.IgnoreCase);
        if (addr.Success && TryParseIpv4(addr.Groups[1].Value, out var ip)) Config.AssignedIp = ip;

        foreach (Match m in Regex.Matches(xml, @"<dns\b[^>]*ip=['""]([^'""]+)", RegexOptions.IgnoreCase))
            if (!Config.DnsServers.Contains(m.Groups[1].Value)) Config.DnsServers.Add(m.Groups[1].Value);
        foreach (Match m in Regex.Matches(xml, @"<dns\b[^>]*domain=['""]([^'""]+)", RegexOptions.IgnoreCase))
            foreach (var d in m.Groups[1].Value.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries))
                if (!Config.DnsSuffixes.Contains(d)) Config.DnsSuffixes.Add(d);

        foreach (Match m in Regex.Matches(xml,
                 @"<split-tunnel-info\b[^>]*ip=['""]([^'""]+)['""][^>]*mask=['""]([^'""]+)",
                 RegexOptions.IgnoreCase))
            if (TryParseIpv4(m.Groups[2].Value, out var mask))
                Config.Routes.Add((m.Groups[1].Value, MaskToPrefix(mask)));

        var mtu = Regex.Match(xml, @"<tunnel-method[^>]*mtu=['""](\d+)", RegexOptions.IgnoreCase);
        if (mtu.Success && uint.TryParse(mtu.Groups[1].Value, out var m2) && m2 >= 576) Config.Mtu = m2;

        Trace($"config: ip={Config.AssignedIpText} dns=[{string.Join(",", Config.DnsServers)}] " +
              $"routes={Config.Routes.Count} mtu={Config.Mtu}");
    }

    private async Task OpenTunnelAsync(CancellationToken ct)
    {
        // The path is /remote/sslvpn-tunnel and the Host header is the literal "sslvpn" --
        // FortiOS routes on that value, not the address dialled. There is no HTTP response:
        // the connection becomes PPP.
        await WriteAsync(Encoding.ASCII.GetBytes(
            $"GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\n" +
            $"Cookie: SVPNCOOKIE={_cookie}\r\n\r\n"), ct);
        Trace("tunnel requested");
    }

    private async Task NegotiatePppAsync(CancellationToken ct)
    {
        var rx = new List<byte>(_spill);
        _spill.Clear();

        var magic = new byte[4];
        Random.Shared.NextBytes(magic);

        async Task SendFrame(ushort proto, CtrlPacket pkt)
        {
            await WriteAsync(FortiFrame.Frame(proto, pkt.Serialize()), ct);
            Trace($"  -> {Proto.Name(proto)} {pkt.CodeName} id={pkt.Id}");
        }

        var mru = new byte[] { (byte)(Config.Mtu >> 8), (byte)Config.Mtu };
        await SendFrame(Proto.Lcp, new CtrlPacket(1, 1, Opt.Concat(
            Opt.Tlv(Opt.Mru, mru),
            Opt.Tlv(Opt.MagicNumber, magic))));

        var lcpOursAcked = false;
        var lcpPeerAcked = false;
        var ipcpSent = false;
        byte ipcpId = 1;
        var wantIp = new byte[4];
        var offerDns = true;

        async Task SendIpcpReq()
        {
            var parts = new List<byte[]> { Opt.Tlv(Opt.IpAddress, wantIp) };
            if (offerDns)
            {
                parts.Add(Opt.Tlv(Opt.PrimaryDns, new byte[4]));
                parts.Add(Opt.Tlv(Opt.SecondaryDns, new byte[4]));
            }
            await SendFrame(Proto.Ipcp, new CtrlPacket(1, ipcpId, Opt.Concat(parts.ToArray())));
        }

        while (true)
        {
            rx.AddRange(await ReadSomeAsync(ct));

            var frames = FortiFrame.Deframe(rx, out var frameError);
            if (frameError is not null) throw new InvalidOperationException(frameError);

            foreach (var (proto, payload) in frames)
            {
                var pkt = CtrlPacket.Parse(payload);
                if (pkt is null) continue;
                Trace($"  <- {Proto.Name(proto)} {pkt.CodeName} id={pkt.Id}");

                if (proto == Proto.Lcp)
                {
                    switch (pkt.Code)
                    {
                        case 1:
                            await SendFrame(Proto.Lcp, pkt with { Code = 2 });
                            lcpPeerAcked = true;
                            break;
                        case 2:
                            lcpOursAcked = true;
                            break;
                        case 3 or 4:
                            await SendFrame(Proto.Lcp,
                                new CtrlPacket(1, (byte)(pkt.Id + 1), Opt.Tlv(Opt.MagicNumber, magic)));
                            break;
                        case 9:
                            await SendFrame(Proto.Lcp, pkt with { Code = 10 });
                            break;
                    }
                }
                else if (proto == Proto.Ipcp)
                {
                    switch (pkt.Code)
                    {
                        case 1:
                            await SendFrame(Proto.Ipcp, pkt with { Code = 2 });
                            break;
                        case 2:
                            foreach (var (t, v) in pkt.Options())
                                if (t == Opt.IpAddress && v.Length == 4) Config.AssignedIp = v;
                            Trace($"IPCP done, IP = {Config.AssignedIpText}");
                            // Any bytes already read past the last PPP frame are the first
                            // tunnel packets; hand them to the data plane rather than lose them.
                            _spill.Clear();
                            _spill.AddRange(rx);
                            return;
                        case 3:     // Nak carries the values the gateway wants us to use
                            foreach (var (t, v) in pkt.Options())
                                if (t == Opt.IpAddress && v.Length == 4) wantIp = v;
                            ipcpId++;
                            await SendIpcpReq();
                            break;
                        case 4:     // Reject means stop offering these at all, not retry them
                            foreach (var (t, _) in pkt.Options())
                                if (t is Opt.PrimaryDns or Opt.SecondaryDns) offerDns = false;
                            ipcpId++;
                            await SendIpcpReq();
                            break;
                    }
                }
            }

            if (lcpOursAcked && lcpPeerAcked && !ipcpSent)
            {
                ipcpSent = true;
                await SendIpcpReq();
            }
        }
    }

    /// <summary>Bytes read from the tunnel during PPP that belong to the data phase -- the
    /// data plane must seed its receive buffer with these before reading more.</summary>
    public byte[] TakeReceiveBacklog()
    {
        var b = _spill.ToArray();
        _spill.Clear();
        return b;
    }

    // ---- logout ------------------------------------------------------------

    /// <summary>Tells the gateway the session is finished, on a short-lived socket of its own
    /// so it never touches the tunnel stream. This gateway holds a session ~30s after the
    /// client vanishes and answers a fresh login from the same address with silence, so a
    /// clean logout is what lets an immediate reconnect succeed.</summary>
    public static async Task LogoutAsync(string host, int port, string cookie, string? pinSha256)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(host, port);
        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host });
        var req = Encoding.ASCII.GetBytes(
            $"GET /remote/logout HTTP/1.1\r\nHost: {host}:{port}\r\n" +
            "User-Agent: Mozilla/5.0 SV1\r\n" +
            $"Cookie: SVPNCOOKIE={cookie}\r\nConnection: close\r\n\r\n");
        await ssl.WriteAsync(req);
        await ssl.FlushAsync();
    }

    // ---- small helpers -----------------------------------------------------

    private static bool TryParseIpv4(string text, out byte[] value)
    {
        value = new byte[4];
        var parts = text.Split('.');
        if (parts.Length != 4) return false;
        for (var i = 0; i < 4; i++)
            if (!byte.TryParse(parts[i], out value[i])) return false;
        return true;
    }

    private static int MaskToPrefix(byte[] mask)
    {
        var bits = 0;
        foreach (var b in mask)
            for (var i = 7; i >= 0; i--)
                if ((b & (1 << i)) != 0) bits++;
        return bits;
    }

    public void Dispose()
    {
        _ssl?.Dispose();
        _tcp?.Dispose();
    }
}
