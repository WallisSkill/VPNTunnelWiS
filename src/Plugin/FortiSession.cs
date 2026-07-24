using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Security.Cryptography.Certificates;
using Windows.Storage.Streams;

namespace FortiVpn;

/// <summary>What the gateway hands back once the tunnel is up.</summary>
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
/// One FortiOS SSL-VPN session, from login through to a negotiated PPP link.
///
/// The whole conversation -- login, VPN allocation, tunnel config, then the tunnel
/// itself -- happens on a single TLS connection, exactly as openfortivpn does it.
/// Opening a second socket for the tunnel is what "Permission denied (5005)" means.
///
/// The socket deliberately is a <see cref="StreamSocket"/> rather than an
/// <c>SslStream</c>: the Windows VPN platform can only adopt a WinRT socket, and it
/// has to adopt the very socket the handshake ran on.
/// </summary>
internal sealed class FortiSession : IDisposable
{
    private readonly string _host;
    private readonly string _port;

    private readonly StreamSocket _socket;
    private DataWriter? _writer;
    private DataReader? _reader;

    private string _cookie = "";

    /// <summary>Bytes read past the end of the last HTTP response.</summary>
    private readonly List<byte> _spill = new();

    public TunnelConfig Config { get; } = new();

    /// <summary>
    /// The transport socket. It exists from construction because the VPN platform will
    /// only take a socket that has not been connected yet -- associating it afterwards is
    /// answered with E_ILLEGAL_STATE_CHANGE.
    /// </summary>
    public StreamSocket Socket => _socket;

    public Action<string>? Log { get; set; }

    /// <summary>
    /// Called when the gateway answers a login with <c>ret=2</c> -- a second-factor
    /// challenge (FortiToken / one-time code), not a rejection. The argument is the
    /// challenge message the gateway sent; the return is the code the user typed, or
    /// null to abandon the sign-in. Null itself when the plugin has no way to prompt,
    /// in which case a gateway that demands a code cannot be signed in to.
    /// </summary>
    public Func<string, string?>? TwoFactorPrompt { get; set; }

    public FortiSession(string host, string port)
    {
        _host = host;
        _port = port;

        _socket = new StreamSocket();

        // A FortiGate presents its own built-in certificate, named after the appliance
        // serial, which chains to nothing any machine trusts. FortiClient accepts it the
        // same way.
        // Only these three errors are waived; a genuine handshake failure still fails.
        _socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.Untrusted);
        _socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.InvalidName);
        _socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.Expired);
    }

    private void Trace(string message) => Log?.Invoke(message);

    public async Task ConnectAsync(string username, string password)
    {
        await _socket.ConnectAsync(new HostName(_host), _port, SocketProtectionLevel.Tls12);
        Trace($"TLS to {_host}:{_port}");

        _writer = new DataWriter(_socket.OutputStream);
        _reader = new DataReader(_socket.InputStream) { InputStreamOptions = InputStreamOptions.Partial };

        await LoginAsync(username, password);
        await RequestAllocationAsync();
        await ReadTunnelConfigAsync();
        await OpenTunnelAsync();
        await NegotiatePppAsync();

        // The platform takes the raw socket from here, so nothing may be left holding
        // its streams. Anything the reader still has buffered would be lost, so say so
        // rather than let a swallowed packet look like a mystery later.
        if (_reader.UnconsumedBufferLength > 0)
            Trace($"warning: {_reader.UnconsumedBufferLength} bytes still unread as the socket is handed over");
        _writer.DetachStream();
        _reader.DetachStream();
        _writer.Dispose();
        _reader.Dispose();
        _writer = null;
        _reader = null;
    }

    // ---- transport helpers -------------------------------------------------

    private async Task WriteAsync(byte[] data)
    {
        _writer!.WriteBytes(data);
        await _writer.StoreAsync();
        await _writer.FlushAsync();
    }

    private async Task<byte[]> ReadSomeAsync()
    {
        var n = await _reader!.LoadAsync(16384);
        if (n == 0) throw new InvalidOperationException("the gateway closed the connection");
        var buf = new byte[n];
        _reader.ReadBytes(buf);
        return buf;
    }

    /// <summary>
    /// Minimal HTTP/1.1 on the raw stream. Returns headers and body separately and keeps
    /// whatever it over-read, because the same connection carries the next request.
    /// </summary>
    private async Task<(string Headers, string Body)> SendAsync(string method, string path, string? formBody = null)
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

        await WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()));

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
                        // Anything beyond Content-Length belongs to the next response.
                        var bodyBytes = acc.Count - headerEnd;
                        if (bodyBytes > want) _spill.AddRange(acc.Skip(headerEnd + want));
                        return (hdr, text.Substring(headerEnd, want));
                    }
                }
            }

            acc.AddRange(await ReadSomeAsync());
        }
    }

    private void TakeCookie(string headers)
    {
        foreach (Match m in Regex.Matches(headers, @"Set-Cookie:\s*SVPNCOOKIE=([^;\r\n]*)([^\r\n]*)", RegexOptions.IgnoreCase))
        {
            // logincheck actively deletes SVPNCOOKIE (expiry in 1984) before the real one
            // is issued further along, so a deletion must not overwrite what we hold.
            var attrs = m.Groups[2].Value;
            if (attrs.Contains("1984") || attrs.Contains("1970")) continue;
            if (m.Groups[1].Value.Length == 0) continue;
            _cookie = m.Groups[1].Value;
        }
    }

    // ---- handshake steps ---------------------------------------------------

    private async Task LoginAsync(string username, string password)
    {
        var (_, loginPage) = await SendAsync("GET", "/remote/login?lang=en");

        string Hidden(string name)
        {
            var m = Regex.Match(loginPage, $@"name=""?{name}""?[^>]*value=""([^""]*)""", RegexOptions.IgnoreCase);
            if (!m.Success) m = Regex.Match(loginPage, $@"value=""([^""]*)""[^>]*name=""?{name}""?", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value : "";
        }

        var form = $"ajax=1&username={Uri.EscapeDataString(username)}" +
                   $"&credential={Uri.EscapeDataString(password)}" +
                   $"&realm={Uri.EscapeDataString(Hidden("realm"))}" +
                   $"&magic={Uri.EscapeDataString(Hidden("magic"))}" +
                   $"&reqid={Uri.EscapeDataString(Hidden("reqid"))}" +
                   $"&grpid={Uri.EscapeDataString(Hidden("grpid"))}" +
                   $"&just_logged_in=1";

        var (loginHdr, loginBody) = await SendAsync("POST", "/remote/logincheck", form);

        // ret=2 is a challenge, not a rejection: the gateway wants a second factor
        // (FortiToken / OTP). The body is a comma-separated list of the fields the
        // follow-up POST has to echo back verbatim -- reqid/polid/grp/portal/magic --
        // alongside the code the user types. This is the same exchange FortiClient and
        // openfortivpn make; skip it and a two-factor account can never sign in.
        if (loginBody.Contains("ret=2"))
        {
            string Field(string name)
            {
                var m = Regex.Match(loginBody, $@"(?:^|,)\s*{name}=([^,\r\n]*)",
                                    RegexOptions.IgnoreCase);
                return m.Success ? m.Groups[1].Value.Trim() : "";
            }

            var chalMsg = Field("chal_msg");
            var code = TwoFactorPrompt?.Invoke(
                chalMsg.Length > 0 ? chalMsg : "Enter your verification code");
            if (string.IsNullOrEmpty(code))
                throw new UnauthorizedAccessException(
                    "this account needs a verification code and none was entered");

            var otpForm = $"username={Uri.EscapeDataString(username)}" +
                          $"&realm={Uri.EscapeDataString(Hidden("realm"))}" +
                          $"&reqid={Uri.EscapeDataString(Field("reqid"))}" +
                          $"&polid={Uri.EscapeDataString(Field("polid"))}" +
                          $"&grp={Uri.EscapeDataString(Field("grp"))}" +
                          $"&portal={Uri.EscapeDataString(Field("portal"))}" +
                          $"&magic={Uri.EscapeDataString(Field("magic"))}" +
                          $"&reqtime={Uri.EscapeDataString(Field("reqtime"))}" +
                          $"&code={Uri.EscapeDataString(code)}" +
                          $"&code2=&just_logged_in=1";

            Trace("second factor requested; submitting the code");
            (loginHdr, loginBody) = await SendAsync("POST", "/remote/logincheck", otpForm);
        }

        // Success takes two shapes: the ajax "ret=1,redir=..." form, and a plain redirect
        // to the portal. Anything else is a rejected credential.
        if (!loginBody.Contains("ret=1") && !loginBody.Contains("/sslvpn/portal.html"))
            throw new UnauthorizedAccessException(
                "sign-in failed (wrong user name, password, or verification code)");

        TakeCookie(loginHdr);

        // The usable SVPNCOOKIE is issued by the host-check step, not by logincheck.
        // Take everything after "redir=" to end of line: the value is itself a query
        // string full of '&', and stopping at the first one drops required parameters.
        var redir = Regex.Match(loginBody, @"redir=(\S+)");
        if (redir.Success)
        {
            var (hcHdr, _) = await SendAsync("GET", redir.Groups[1].Value.Trim());
            TakeCookie(hcHdr);
        }
        else
        {
            var (pHdr, _) = await SendAsync("GET", "/sslvpn/portal.html");
            TakeCookie(pHdr);
        }

        if (_cookie.Length == 0) throw new UnauthorizedAccessException("no SVPNCOOKIE was issued");
        Trace($"sign-in OK (cookie len={_cookie.Length})");
    }

    private async Task RequestAllocationAsync()
    {
        // Nobody reads these two bodies. They exist because the gateway will not hand out
        // a tunnel until the session has been allocated one; without them every tunnel
        // request comes back "Permission denied (5005)". /remote/index answering 403 is
        // normal and not a failure.
        await SendAsync("GET", "/remote/index");
        await SendAsync("GET", "/remote/fortisslvpn");
    }

    private async Task ReadTunnelConfigAsync()
    {
        var (xmlHdr, xml) = await SendAsync("GET", "/remote/fortisslvpn_xml");

        // Verbatim, because every route and DNS server we get comes out of this one
        // response, and parsing it to nothing looks identical to the gateway sending
        // nothing. The body carries no credential -- the cookie travels in the header.
        Trace($"fortisslvpn_xml: {xmlHdr.Split('\r')[0]} body={xml.Length}");
        Trace(xml.Length > 900 ? xml[..900] : xml);

        var addr = Regex.Match(xml, @"<assigned-addr[^>]*ipv4=['""]([^'""]+)", RegexOptions.IgnoreCase);
        if (addr.Success && TryParseIpv4(addr.Groups[1].Value, out var ip)) Config.AssignedIp = ip;

        // DNS cannot come from IPCP on this gateway -- it rejects both options outright --
        // so the XML is the only source. FortiClient reads it from here too.
        foreach (Match m in Regex.Matches(xml, @"<dns\b[^>]*ip=['""]([^'""]+)", RegexOptions.IgnoreCase))
            if (!Config.DnsServers.Contains(m.Groups[1].Value)) Config.DnsServers.Add(m.Groups[1].Value);
        foreach (Match m in Regex.Matches(xml, @"<dns\b[^>]*domain=['""]([^'""]+)", RegexOptions.IgnoreCase))
            foreach (var d in m.Groups[1].Value.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries))
                if (!Config.DnsSuffixes.Contains(d)) Config.DnsSuffixes.Add(d);

        foreach (Match m in Regex.Matches(xml, @"<split-tunnel-info\b[^>]*ip=['""]([^'""]+)['""][^>]*mask=['""]([^'""]+)", RegexOptions.IgnoreCase))
            if (TryParseIpv4(m.Groups[2].Value, out var mask))
                Config.Routes.Add((m.Groups[1].Value, MaskToPrefix(mask)));

        var mtu = Regex.Match(xml, @"<tunnel-method[^>]*mtu=['""](\d+)", RegexOptions.IgnoreCase);
        if (mtu.Success && uint.TryParse(mtu.Groups[1].Value, out var m2) && m2 >= 576) Config.Mtu = m2;

        Trace($"config: ip={Config.AssignedIpText} dns=[{string.Join(",", Config.DnsServers)}] " +
              $"routes={Config.Routes.Count} mtu={Config.Mtu}");
    }

    private async Task OpenTunnelAsync()
    {
        // Two details that were wrong for a long time: the path is /remote/sslvpn-tunnel
        // (not /remote/network), and the Host header is the literal string "sslvpn" --
        // FortiOS routes on that value, not on the address we dialled. Nothing else is
        // sent, and there is no HTTP response: the connection becomes PPP.
        await WriteAsync(Encoding.ASCII.GetBytes(
            $"GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\n" +
            $"Cookie: SVPNCOOKIE={_cookie}\r\n\r\n"));
        Trace("tunnel requested");
    }

    private async Task NegotiatePppAsync()
    {
        var rx = new List<byte>(_spill);
        _spill.Clear();

        var magic = new byte[4];
        new Random().NextBytes(magic);

        async Task SendFrame(ushort proto, CtrlPacket pkt)
        {
            await WriteAsync(FortiFrame.Frame(proto, pkt.Serialize()));
            Trace($"  -> {Proto.Name(proto)} {pkt.CodeName} id={pkt.Id}");
        }

        // MRU and a magic number only. openfortivpn runs pppd with noaccomp, nopcomp and
        // default-asyncmap, so it never offers ACFC, PFC or an ACCM either.
        var mru = new byte[] { (byte)(Config.Mtu >> 8), (byte)Config.Mtu };
        await SendFrame(Proto.Lcp, new CtrlPacket(1, 1, Opt.Concat(
            Opt.Tlv(Opt.Mru, mru),
            Opt.Tlv(Opt.MagicNumber, magic))));

        var lcpOursAcked = false;
        var lcpPeerAcked = false;
        var ipcpSent = false;
        byte ipcpId = 1;
        var wantIp = new byte[4];

        // The DNS options are the ones this gateway refuses outright, so they are offered
        // separately and dropped for good once rejected rather than retried.
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
            rx.AddRange(await ReadSomeAsync());

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

    /// <summary>
    /// The session cookie. Only ever used to hand this session's own logout to
    /// <see cref="LogoutAsync"/>, which runs on a socket this object no longer owns.
    /// </summary>
    public string Cookie => _cookie;

    /// <summary>
    /// Tells the gateway the session is finished, on a socket of its own.
    ///
    /// It cannot go down the session's own socket: by the time a session is being replaced
    /// the platform has adopted that socket as the tunnel transport and writing HTTP into it
    /// would corrupt the frame stream. So this opens a second, short-lived connection purely
    /// to say goodbye, and closes it again.
    ///
    /// Why bother: this gateway is configured <c>tun-user-ses-timeout='30'</c> with
    /// <c>check-src-ip='1'</c>, so it holds a session open for thirty seconds after the
    /// client vanishes and answers a fresh login from the same address with silence. That
    /// silence is what the twenty-five second handshake bound catches, and what reads as a
    /// bare "timeout" when reconnecting straight after a disconnect.
    ///
    /// The response is not read. Nothing here depends on what the gateway says back, and
    /// waiting for it would only add a second way for a reconnect to stall.
    /// </summary>
    public static async Task LogoutAsync(string host, string port, string cookie)
    {
        using var socket = new StreamSocket();
        socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.Untrusted);
        socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.InvalidName);
        socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.Expired);

        await socket.ConnectAsync(new HostName(host), port, SocketProtectionLevel.Tls12);

        var writer = new DataWriter(socket.OutputStream);
        try
        {
            writer.WriteBytes(Encoding.ASCII.GetBytes(
                $"GET /remote/logout HTTP/1.1\r\n" +
                $"Host: {host}:{port}\r\n" +
                "User-Agent: Mozilla/5.0 SV1\r\n" +
                $"Cookie: SVPNCOOKIE={cookie}\r\n" +
                "Connection: close\r\n\r\n"));
            await writer.StoreAsync();
            await writer.FlushAsync();
        }
        finally
        {
            // Detached, not disposed: disposing the writer closes the socket's output
            // stream, and the socket's own Dispose is what should be doing that.
            writer.DetachStream();
            writer.Dispose();
        }
    }

    public void Dispose()
    {
        _writer?.Dispose();
        _reader?.Dispose();
        _socket?.Dispose();
    }
}
