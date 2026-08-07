using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FortiVpn;

/// <summary>
/// Cross-platform FortiGate SSL-VPN client. Signs in (with a second factor when the account
/// has one), negotiates the PPP link, opens a tun/utun interface and pumps IP packets between
/// it and the tunnel until interrupted -- the macOS/Linux counterpart to the Windows plugin,
/// built on the same protocol core.
///
/// Root is required (opening the interface and changing routes), so it runs under sudo. The
/// password and any one-time code are entered by whoever runs it; nothing stores them.
/// </summary>
internal static class Program
{
    private static bool _verbose;

    private static int Main(string[] rawArgs)
    {
        try { return Run(rawArgs).GetAwaiter().GetResult(); }
        catch (Exception e)
        {
            Console.Error.WriteLine($"error: {e.Message}");
            return 1;
        }
    }

    private static async Task<int> Run(string[] args)
    {
        if (args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
        {
            Usage();
            return args.Length == 0 ? 2 : 0;
        }

        string? gateway = null, user = null, pin = null, otp = null;
        var passwordStdin = false;
        var forceFull = false;

        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            switch (a)
            {
                case "-v": case "--verbose": _verbose = true; break;
                case "--full": forceFull = true; break;
                case "--password-stdin": passwordStdin = true; break;
                case "-u": case "--user": user = args[++i]; break;
                case "--trusted-cert": pin = args[++i]; break;
                case "--otp": otp = args[++i]; break;
                default:
                    if (a.StartsWith('-')) { Console.Error.WriteLine($"unknown option: {a}"); return 2; }
                    gateway = a;
                    break;
            }
        }

        if (gateway is null) { Usage(); return 2; }
        var (host, port) = ParseGateway(gateway);

        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            Console.Error.WriteLine(
                "This client is for macOS and Linux. On Windows, install the VPN Platform plugin.");
            return 2;
        }

        user ??= Prompt($"Username for {host}: ");
        var password = passwordStdin ? (Console.In.ReadLine() ?? "") : ReadSecret($"Password for {user}: ");

        var gatewayIp = ResolveIpv4(host);

        var client = new FortiClient(host, port, pin) { Log = Trace };
        client.TwoFactorPrompt = challenge =>
            otp ?? ReadSecret($"{challenge}: ");

        Console.WriteLine($"Connecting to {host}:{port} ...");
        using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        try
        {
            await client.ConnectAsync(user, password, connectCts.Token);
        }
        catch (Exception e)
        {
            if (client.ServerCertSha256 is not null && pin is not null)
                Console.Error.WriteLine($"(gateway certificate fingerprint: {client.ServerCertSha256})");
            Console.Error.WriteLine($"connect failed: {e.Message}");
            return 1;
        }

        var cfg = client.Config;
        var fullTunnel = forceFull || cfg.Routes.Count == 0;

        Console.WriteLine($"Connected. IP {cfg.AssignedIpText}, MTU {cfg.Mtu}, " +
                          $"{(fullTunnel ? "full tunnel" : $"{cfg.Routes.Count} split route(s)")}.");
        if (client.ServerCertSha256 is not null && pin is null)
            Console.WriteLine($"Gateway certificate: {client.ServerCertSha256}\n" +
                              $"  (pin it next time with --trusted-cert {client.ServerCertSha256})");

        using var tun = TunFactory.Open();
        Console.WriteLine($"Interface {tun.Name} up.");

        var routes = new RouteManager(Trace);
        routes.Configure(tun, cfg, gatewayIp, fullTunnel);

        Console.WriteLine("Tunnel is up. Press Ctrl-C to disconnect.");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, ev) => { ev.Cancel = true; cts.Cancel(); };

        // SIGTERM too, not just Ctrl-C. Anything that supervises this process -- the desktop
        // integration's Disconnect button, systemd, a logout -- stops it with a signal rather
        // than a keystroke, and without this the teardown below never runs: the routes and
        // /etc/resolv.conf would be left rewritten with the tunnel gone.
        using var sigterm = PosixSignalRegistration.Create(
            PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; cts.Cancel(); });

        try
        {
            await RunDataPlane(client, tun, cts.Token);
        }
        catch (OperationCanceledException) { }
        finally
        {
            Console.WriteLine("\nDisconnecting ...");
            routes.Teardown();
            try { await FortiClient.LogoutAsync(host, port, client.Cookie, pin); } catch { }
            client.Dispose();
        }

        return 0;
    }

    /// <summary>The two packet pumps plus PPP keepalive, all over the one tunnel stream.</summary>
    private static async Task RunDataPlane(FortiClient client, ITunDevice tun, CancellationToken ct)
    {
        var ssl = client.Stream;
        var writeLock = new SemaphoreSlim(1, 1);

        async Task SendFrame(ushort proto, byte[] body)
        {
            await writeLock.WaitAsync(ct);
            try { await ssl.WriteAsync(FortiFrame.Frame(proto, body), ct); await ssl.FlushAsync(ct); }
            finally { writeLock.Release(); }
        }

        // tun -> tunnel: blocking reads on a dedicated thread so they never stall the loop;
        // closing the tun fd on teardown makes Read return 0 and ends it.
        var up = Task.Run(() =>
        {
            var buf = new byte[2048];
            while (!ct.IsCancellationRequested)
            {
                var n = tun.Read(buf);
                if (n <= 0) break;
                SendFrame(Proto.Ipv4, buf[..n]).GetAwaiter().GetResult();
            }
        }, ct);

        // tunnel -> tun, plus answering the gateway's LCP echo and honouring a hangup.
        var down = Task.Run(async () =>
        {
            var rx = new System.Collections.Generic.List<byte>(client.TakeReceiveBacklog());
            var scratch = new byte[16384];
            while (!ct.IsCancellationRequested)
            {
                // Drain anything already buffered before blocking on the socket again.
                var frames = FortiFrame.Deframe(rx, out var err);
                if (err is not null) throw new InvalidOperationException(err);
                foreach (var (proto, payload) in frames)
                {
                    if (proto == Proto.Ipv4) { tun.Write(payload); continue; }
                    if (proto == Proto.Lcp)
                    {
                        var pkt = CtrlPacket.Parse(payload);
                        if (pkt is null) continue;
                        if (pkt.Code == 9) await SendFrame(Proto.Lcp, (pkt with { Code = 10 }).Serialize());
                        else if (pkt.Code == 5)   // Terminate-Request: gateway is hanging up
                        { await SendFrame(Proto.Lcp, (pkt with { Code = 6 }).Serialize()); return; }
                    }
                }

                var n = await ssl.ReadAsync(scratch, ct);
                if (n == 0) { Trace("tunnel closed by gateway"); return; }
                rx.AddRange(scratch[..n]);
            }
        }, ct);

        // A quiet PPP keepalive: an Echo-Request every 20s. If the link is dead the read
        // side sees the close; this just keeps a NAT/idle timer from dropping us first.
        var keepalive = Task.Run(async () =>
        {
            var magic = new byte[4]; Random.Shared.NextBytes(magic);
            byte id = 1;
            while (!ct.IsCancellationRequested)
            {
                try { await Task.Delay(TimeSpan.FromSeconds(20), ct); } catch { break; }
                await SendFrame(Proto.Lcp, new CtrlPacket(9, id++, Opt.Tlv(Opt.MagicNumber, magic)).Serialize());
            }
        }, ct);

        await Task.WhenAny(up, down);
    }

    // ---- input helpers -----------------------------------------------------

    private static string Prompt(string label)
    {
        Console.Write(label);
        return Console.ReadLine() ?? "";
    }

    /// <summary>Reads a line without echoing it. Falls back to a plain read when there is no
    /// interactive console (piped input), so automation still works.</summary>
    private static string ReadSecret(string label)
    {
        Console.Write(label);
        if (Console.IsInputRedirected) return Console.In.ReadLine() ?? "";

        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
            if (key.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; continue; }
            if (!char.IsControl(key.KeyChar)) sb.Append(key.KeyChar);
        }
        return sb.ToString();
    }

    // ---- parsing helpers ---------------------------------------------------

    private static (string Host, int Port) ParseGateway(string s)
    {
        s = s.Trim();
        var scheme = s.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) s = s[(scheme + 3)..];
        var slash = s.IndexOf('/');
        if (slash >= 0) s = s[..slash];               // drop any path
        var colon = s.LastIndexOf(':');
        if (colon >= 0 && int.TryParse(s[(colon + 1)..], out var p))
            return (s[..colon], p);
        return (s, 443);
    }

    private static string ResolveIpv4(string host)
    {
        if (IPAddress.TryParse(host, out var direct)) return direct.ToString();
        var a = Dns.GetHostAddresses(host).FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
        return a?.ToString() ?? host;
    }

    private static void Trace(string m) { if (_verbose) Console.WriteLine($"[trace] {m}"); }

    private static void Usage()
    {
        Console.WriteLine(@"fortivpn -- FortiGate SSL-VPN client for macOS and Linux

USAGE
    sudo fortivpn <gateway> [options]

    <gateway>   host, host:port, or https://host:port  (default port 443)

OPTIONS
    -u, --user <name>       account name (prompted if omitted)
    --password-stdin        read the password from stdin instead of prompting
    --otp <code>            pass the second-factor code non-interactively
    --trusted-cert <sha256> pin the gateway certificate; refuse any other
    --full                  force a full tunnel even if the portal pushes split routes
    -v, --verbose           print the protocol trace
    -h, --help              this text

Needs root (opening the tun/utun interface and setting routes), so run under sudo.
The password and one-time code are entered at runtime and never stored.");
    }
}
