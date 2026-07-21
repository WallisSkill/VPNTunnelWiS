using FortiVpn;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;

// FortiOS SSL-VPN tunnel probe -- everything on ONE TLS connection.
//
// Earlier attempts logged in with HttpClient and then opened a fresh socket for
// /remote/network, which the gateway answered with "Permission denied" (5005). A
// FortiClient log proved tunnel mode does work for the account in question, so the
// refusal is about HOW we ask.
//
// openfortivpn keeps a single TLS handle from login through to the tunnel, so this
// version does the same: login, host check, tunnel config and /remote/network all
// travel over the same connection.
//
// It sends nothing INTO the tunnel -- it only reads the reply and hex-dumps it.
// You type the password; it is never echoed, stored, or printed. Cookie values are
// never printed either.

// Gateway on the command line: "TunnelProbe vpn.example.com 10443". Nothing about a
// particular network belongs in this file.
if (args.Length < 1)
{
    Console.WriteLine("Usage: TunnelProbe <host> [port]");
    return;
}

var Host = args[0];
var Port = args.Length > 1 ? int.Parse(args[1]) : 443;

using var tcp = new TcpClient();
await tcp.ConnectAsync(Host, Port);
using var tls = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
{
    TargetHost = Host,
    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
});
Console.WriteLine($"TLS {tls.SslProtocol} to {Host}:{Port}");

var cookie = "";
var buffered = new List<byte>();   // bytes read past the end of the previous response

// Minimal HTTP/1.1 over the raw stream. Returns headers and body separately so the
// caller can keep using the same connection afterwards.
async Task<(string Headers, string Body)> Send(string method, string path, string? formBody = null)
{
    var sb = new StringBuilder();
    sb.Append($"{method} {path} HTTP/1.1\r\n");
    sb.Append($"Host: {Host}:{Port}\r\n");
    sb.Append("User-Agent: Mozilla/5.0 SV1\r\n");
    sb.Append("Accept: */*\r\n");
    sb.Append("Connection: Keep-Alive\r\n");
    if (cookie.Length > 0) sb.Append($"Cookie: SVPNCOOKIE={cookie}\r\n");
    if (formBody is not null)
    {
        sb.Append("Content-Type: application/x-www-form-urlencoded\r\n");
        sb.Append($"Content-Length: {Encoding.ASCII.GetByteCount(formBody)}\r\n");
    }
    sb.Append("\r\n");
    if (formBody is not null) sb.Append(formBody);

    await tls.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()));
    await tls.FlushAsync();

    var buf = new byte[16384];
    var acc = new List<byte>(buffered);
    buffered.Clear();
    var headerEnd = -1;
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

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
            // Chunked bodies end with a zero-length chunk; fixed bodies end at Content-Length.
            if (hdr.Contains("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase))
            {
                if (text.IndexOf("\r\n0\r\n\r\n", headerEnd, StringComparison.Ordinal) >= 0)
                    return (hdr, text[headerEnd..]);
            }
            else
            {
                var cl = Regex.Match(hdr, @"Content-Length:\s*(\d+)", RegexOptions.IgnoreCase);
                var want = cl.Success ? int.Parse(cl.Groups[1].Value) : 0;
                if (acc.Count - headerEnd >= want) return (hdr, text[headerEnd..]);
            }
        }

        int n;
        try { n = await tls.ReadAsync(buf, cts.Token); }
        catch (OperationCanceledException) { return (headerEnd >= 0 ? text[..headerEnd] : text, ""); }
        if (n == 0) return (headerEnd >= 0 ? text[..headerEnd] : text, headerEnd >= 0 ? text[headerEnd..] : "");
        acc.AddRange(buf.AsSpan(0, n).ToArray());
    }
}

void TakeCookie(string headers)
{
    foreach (Match m in Regex.Matches(headers, @"Set-Cookie:\s*SVPNCOOKIE=([^;\r\n]*)([^\r\n]*)", RegexOptions.IgnoreCase))
    {
        var attrs = m.Groups[2].Value;
        if (attrs.Contains("1984") || attrs.Contains("1970")) continue;  // deletion
        if (m.Groups[1].Value.Length == 0) continue;
        cookie = m.Groups[1].Value;
    }
}

Console.WriteLine("\n=== 1. GET /remote/login ===");
var (_, loginPage) = await Send("GET", "/remote/login?lang=en");

string Hidden(string name)
{
    var m = Regex.Match(loginPage, $@"name=""?{name}""?[^>]*value=""([^""]*)""", RegexOptions.IgnoreCase);
    if (!m.Success) m = Regex.Match(loginPage, $@"value=""([^""]*)""[^>]*name=""?{name}""?", RegexOptions.IgnoreCase);
    return m.Success ? m.Groups[1].Value : "";
}

Console.Write("Username: ");
var user = Console.ReadLine() ?? "";
Console.Write("Password (not echoed): ");
var pw = new StringBuilder();
while (true)
{
    var k = Console.ReadKey(intercept: true);
    if (k.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
    if (k.Key == ConsoleKey.Backspace) { if (pw.Length > 0) pw.Length--; continue; }
    pw.Append(k.KeyChar);
}

var form = $"ajax=1&username={Uri.EscapeDataString(user)}&credential={Uri.EscapeDataString(pw.ToString())}" +
           $"&realm={Uri.EscapeDataString(Hidden("realm"))}&magic={Uri.EscapeDataString(Hidden("magic"))}" +
           $"&reqid={Uri.EscapeDataString(Hidden("reqid"))}&grpid={Uri.EscapeDataString(Hidden("grpid"))}" +
           $"&just_logged_in=1";
pw.Clear();

Console.WriteLine("\n=== 2. POST /remote/logincheck ===");
var (loginHdr, loginBody) = await Send("POST", "/remote/logincheck", form);

// Two shapes mean success: the ajax form "ret=1,redir=..." and a plain HTML redirect to
// the portal. Only an error page means the credentials were rejected.
var ok = loginBody.Contains("ret=1") || loginBody.Contains("/sslvpn/portal.html");
Console.WriteLine($"  {(ok ? "login OK" : "login FAILED")}: {loginBody.Trim().Replace("\n", " ")}");
foreach (var line in loginHdr.Split("\r\n").Where(l => l.StartsWith("Set-Cookie", StringComparison.OrdinalIgnoreCase)))
    Console.WriteLine($"  hdr: {Regex.Replace(line, @"=([^;]{4})[^;]*", "=$1...")}");
if (!ok) return;
TakeCookie(loginHdr);

// Host check is where the usable SVPNCOOKIE is issued when the ajax path is taken.
var redir = Regex.Match(loginBody, @"redir=(\S+)");
if (redir.Success)
{
    Console.WriteLine("\n=== 3. GET host check (fetches the real SVPNCOOKIE) ===");
    var (hcHdr, _) = await Send("GET", redir.Groups[1].Value.Trim());
    TakeCookie(hcHdr);
}
else
{
    Console.WriteLine("\n=== 3. GET /sslvpn/portal.html ===");
    var (pHdr, _) = await Send("GET", "/sslvpn/portal.html");
    TakeCookie(pHdr);
}
if (cookie.Length == 0) { Console.WriteLine("  no SVPNCOOKIE was obtained"); return; }
Console.WriteLine($"  SVPNCOOKIE OK (len={cookie.Length})");

// The gateway will not hand out a tunnel until the session has actually been
// allocated one. openfortivpn's auth_request_vpn_allocation does this with two
// plain GETs whose bodies nobody reads; skipping them is what earned us
// "Permission denied (5005)" on every previous attempt.
Console.WriteLine("\n=== 4. GET /remote/index + /remote/fortisslvpn (xin cap phat VPN) ===");
var (idxHdr, _) = await Send("GET", "/remote/index");
Console.WriteLine($"  /remote/index      -> {idxHdr.Split("\r\n")[0]}");
var (fsvHdr, _) = await Send("GET", "/remote/fortisslvpn");
Console.WriteLine($"  /remote/fortisslvpn -> {fsvHdr.Split("\r\n")[0]}");

Console.WriteLine("\n=== 5. GET /remote/fortisslvpn_xml (cau hinh tunnel) ===");
var (_, xml) = await Send("GET", "/remote/fortisslvpn_xml");
foreach (Match m in Regex.Matches(xml, @"<(ipv4|dns|split-tunnel-info|assigned-addr)[^>]*>", RegexOptions.IgnoreCase))
    Console.WriteLine($"  {m.Value}");
foreach (Match m in Regex.Matches(xml, @"(?:ip|addr|dns)=""([^""]+)""", RegexOptions.IgnoreCase))
    Console.WriteLine($"  cfg: {m.Value}");

// The real tunnel endpoint. Two details matter and both were wrong before:
// the path is /remote/sslvpn-tunnel (not /remote/network), and the Host header
// is the literal string "sslvpn" -- FortiOS routes on that value, not on the
// address we dialled. Nothing else is sent: no User-Agent, no Accept.
//
// There is no HTTP response to this. On success the gateway switches the
// connection straight to PPP, so we read raw bytes and dump them.
Console.WriteLine("\n=== 6. GET /remote/sslvpn-tunnel (chuyen sang PPP) ===");
await tls.WriteAsync(Encoding.ASCII.GetBytes(
    $"GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\n" +
    $"Cookie: SVPNCOOKIE={cookie}\r\n\r\n"));
await tls.FlushAsync();

// The gateway said nothing at all on the previous run, which is expected: it waits
// for the client to open the PPP conversation. openfortivpn has pppd already
// running before it asks for the tunnel, so pppd's Configure-Request is the first
// thing on the wire. We do the same by hand.
var rx = new List<byte>(buffered);
var magic = new byte[4];
Random.Shared.NextBytes(magic);

async Task SendFrame(ushort proto, CtrlPacket pkt, string label)
{
    await tls.WriteAsync(FortiFrame.Frame(proto, pkt.Serialize()));
    await tls.FlushAsync();
    Console.WriteLine($"  -> {Proto.Name(proto)} {pkt.CodeName} id={pkt.Id}" +
                      (label.Length > 0 ? $" [{label}]" : ""));
}

// MRU 1354 and a magic number only: pppd is told "noaccomp", "nopcomp" and
// "default-asyncmap", so it never offers ACFC, PFC or an ACCM either.
var lcpReq = new CtrlPacket(1, 1, Opt.Concat(
    Opt.Tlv(Opt.Mru, 0x05, 0x4A),
    Opt.Tlv(Opt.MagicNumber, magic)));
Console.WriteLine();
await SendFrame(Proto.Lcp, lcpReq, "MRU=1354");

var lcpOursAcked = false;
var lcpPeerAcked = false;
var ipcpSent = false;
byte ipcpId = 1;
var wantIp = new byte[4];
var wantDns1 = new byte[4];
var wantDns2 = new byte[4];

// The DNS options are the ones a gateway is most likely to refuse outright, so
// they are offered separately and dropped for good once rejected.
var offerDns = true;

async Task SendIpcpReq()
{
    var parts = new List<byte[]> { Opt.Tlv(Opt.IpAddress, wantIp) };
    if (offerDns)
    {
        parts.Add(Opt.Tlv(Opt.PrimaryDns, wantDns1));
        parts.Add(Opt.Tlv(Opt.SecondaryDns, wantDns2));
    }
    var pkt = new CtrlPacket(1, ipcpId, Opt.Concat(parts.ToArray()));
    await SendFrame(Proto.Ipcp, pkt,
        $"IP={string.Join(".", wantIp)}{(offerDns ? "" : ", not asking for DNS")}");
}

var buf = new byte[16384];
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
try
{
    while (!deadline.IsCancellationRequested)
    {
        var n = await tls.ReadAsync(buf, deadline.Token);
        if (n == 0) { Console.WriteLine("  server closed the connection"); break; }
        rx.AddRange(buf.AsSpan(0, n).ToArray());

        var frames = FortiFrame.Deframe(rx, out var frameError);
        if (frameError is not null)
        {
            Console.WriteLine($"\n  FRAMING ERROR: {frameError}");
            foreach (var i in Enumerable.Range(0, Math.Min(4, (rx.Count + 15) / 16)).Select(k => k * 16))
                Console.WriteLine($"  {i:X4}  {string.Join(" ", rx.Skip(i).Take(16).Select(x => x.ToString("X2")))}");
            break;
        }

        foreach (var (proto, payload) in frames)
        {
            var pkt = CtrlPacket.Parse(payload);
            if (pkt is null)
            {
                Console.WriteLine($"  <- {Proto.Name(proto)} {payload.Length} bytes of data");
                continue;
            }

            var opts = pkt.Options();
            var shown = opts.Count > 0
                ? " " + string.Join(", ", opts.Select(o => Opt.Describe(proto, o.Type, o.Value)))
                : "";
            Console.WriteLine($"  <- {Proto.Name(proto)} {pkt.CodeName} id={pkt.Id}{shown}");

            if (proto == Proto.Lcp)
            {
                switch (pkt.Code)
                {
                    case 1:     // peer's Configure-Request: accept it wholesale
                        await SendFrame(Proto.Lcp, pkt with { Code = 2 }, "accepted");
                        lcpPeerAcked = true;
                        break;
                    case 2:
                        lcpOursAcked = true;
                        break;
                    case 3 or 4: // Nak/Reject: drop what it disliked and retry
                        await SendFrame(Proto.Lcp,
                            new CtrlPacket(1, (byte)(pkt.Id + 1), Opt.Tlv(Opt.MagicNumber, magic)),
                            "trimmed down after Nak/Reject");
                        break;
                    case 9:     // Echo-Request
                        await SendFrame(Proto.Lcp, pkt with { Code = 10 }, "");
                        break;
                }
            }
            else if (proto == Proto.Ipcp)
            {
                switch (pkt.Code)
                {
                    case 1:
                        await SendFrame(Proto.Ipcp, pkt with { Code = 2 }, "accepted");
                        break;
                    case 2:
                        Console.WriteLine("\n  >>> IPCP IS UP. Addresses assigned:");
                        foreach (var (t, v) in opts)
                            Console.WriteLine($"        {Opt.IpcpName(t)}: {string.Join(".", v)}");
                        Console.WriteLine("\n  >>> TUNNEL IS WORKING. The PPP layer is done.");
                        return;
                    case 3:     // Nak carries the values the gateway wants us to use
                        foreach (var (t, v) in opts)
                        {
                            if (t == Opt.IpAddress && v.Length == 4) wantIp = v;
                            else if (t == Opt.PrimaryDns && v.Length == 4) wantDns1 = v;
                            else if (t == Opt.SecondaryDns && v.Length == 4) wantDns2 = v;
                        }
                        ipcpId++;
                        await SendIpcpReq();
                        break;
                    case 4:     // Reject means stop offering these at all, not retry them
                        foreach (var (t, _) in opts)
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
            Console.WriteLine("\n  >>> LCP IS UP. Moving to IPCP to ask for IP + DNS.");
            await SendIpcpReq();
        }
    }
}
catch (OperationCanceledException)
{
    Console.WriteLine($"\n  30 seconds elapsed. {rx.Count} bytes left that never formed a frame:");
    foreach (var i in Enumerable.Range(0, (rx.Count + 15) / 16).Select(k => k * 16))
    {
        var len = Math.Min(16, rx.Count - i);
        var hex = string.Join(" ", rx.Skip(i).Take(len).Select(x => x.ToString("X2")));
        Console.WriteLine($"  {i:X4}  {hex}");
    }
}
