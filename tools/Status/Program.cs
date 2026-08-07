// A read-only window onto a running tunnel. The plugin logs everything to a file inside
// its own app-container temp folder (see FortiPlugin.Trace); nothing here writes to that
// file or talks to the gateway -- it only reads what the plugin already recorded and lays
// it out so "am I on full or split tunnel, and is traffic actually moving" is answerable at
// a glance. That question is otherwise buried in a log that grows by thousands of lines a
// minute.
//
//     dotnet run --project tools\Status              # live dashboard, refreshes every second
//     dotnet run --project tools\Status -- --once    # print once and exit (for scripts)
//     dotnet run --project tools\Status -- collect    # gather the logs into a zip for support
//     dotnet run --project tools\Status -- --path C:\some\forti-plugin.log
//
// The log carries no credential and no gateway password -- only the address, the assigned
// IP, route/DNS assignments and packet counters -- so collecting it is safe to hand to
// whoever is helping. The address is the one thing in it that identifies a network; the
// collect step says so before it writes the zip.

using System.IO.Compression;
using System.Text.RegularExpressions;

namespace Status;

internal static class Program
{
    // Fixed because it is derived from the package Identity Name, which must never change
    // (it is what keeps an installed connection bound to the provider). If a future rename
    // ever did change it, --path is the escape hatch.
    private const string PackageGlob = "FortiGateSslVpn.Plugin_*";

    private static int Main(string[] args)
    {
        var once = args.Contains("--once");
        var collect = args.Contains("collect") || args.Contains("--collect");

        string? path = null;
        var p = Array.IndexOf(args, "--path");
        if (p >= 0 && p + 1 < args.Length) path = args[p + 1];

        var tempLog = path ?? FindLog("AC\\Temp", "forti-plugin.log");

        if (collect)
            return Collect(tempLog);

        if (tempLog is null || !File.Exists(tempLog))
        {
            Console.WriteLine("No plugin log found yet.");
            Console.WriteLine("Looked for: %LOCALAPPDATA%\\Packages\\" + PackageGlob +
                              "\\AC\\Temp\\forti-plugin.log");
            Console.WriteLine();
            Console.WriteLine("Connect the VPN once and the plugin will create it, then run this again.");
            Console.WriteLine("Or point at a copied log with:  --path <file>");
            return 1;
        }

        if (once)
        {
            Render(Parse(ReadTail(tempLog)), tempLog, null);
            return 0;
        }

        Console.CancelKeyPress += (_, e) => { e.Cancel = false; Console.CursorVisible = true; };
        Console.CursorVisible = false;
        State? previous = null;
        DateTime previousAt = DateTime.MinValue;
        try
        {
            while (true)
            {
                var state = Parse(ReadTail(tempLog));
                double? rate = null;
                if (previous is not null && state.Received >= previous.Received)
                {
                    var secs = (DateTime.Now - previousAt).TotalSeconds;
                    if (secs > 0) rate = (state.Received - previous.Received) / secs;
                }
                Render(state, tempLog, rate);
                previous = state;
                previousAt = DateTime.Now;
                Thread.Sleep(1000);
            }
        }
        finally
        {
            Console.CursorVisible = true;
        }
    }

    // ---- discovery ---------------------------------------------------------

    private static string? FindLog(string subdir, string file)
    {
        var packages = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Packages");
        if (!Directory.Exists(packages)) return null;

        return Directory.EnumerateDirectories(packages, PackageGlob)
            .Select(d => Path.Combine(d, subdir, file))
            .Where(File.Exists)
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();
    }

    // Reading only the tail keeps this cheap on a log that grows by thousands of lines a
    // minute. 128 KB is far more than one connection's worth of interesting lines.
    private static string ReadTail(string path, int bytes = 128 * 1024)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                          FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length > bytes) fs.Seek(-bytes, SeekOrigin.End);
            using var sr = new StreamReader(fs);
            return sr.ReadToEnd();
        }
        catch (Exception ex)
        {
            return $"__READ_ERROR__ {ex.Message}";
        }
    }

    // ---- parsing -----------------------------------------------------------

    private sealed class State
    {
        public string Phase = "Idle";          // Idle / Connecting / Up / Failed
        public string LastLineTime = "";
        public string Target = "";
        public string Ip = "";
        public string Mtu = "";
        public string Mode = "";                // "full" / "split"
        public string Routes = "";
        public string Dns = "";
        public string Suffix = "";
        public long Sent;
        public long Received;
        public int IdleSeconds = -1;
        public bool AwaitingTwoFactor;
        public string LastError = "";
        public string ReadError = "";
    }

    private static readonly Regex TimeStamp = new(@"^(\d\d:\d\d:\d\d\.\d\d\d)\s+(.*)$");
    private static readonly Regex TunnelUp = new(
        @"tunnel up, IP (\S+) mtu=(\d+) routes=\[([^\]]*)\](\s+split)? dns=\[([^\]]*)\] suffix=\[([^\]]*)\]");
    private static readonly Regex Heartbeat = new(@"heartbeat: sent=(\d+) received=(\d+) idle=(\d+)s");

    private static State Parse(string tail)
    {
        var s = new State();
        if (tail.StartsWith("__READ_ERROR__"))
        {
            s.ReadError = tail["__READ_ERROR__".Length..].Trim();
            return s;
        }

        foreach (var raw in tail.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var m = TimeStamp.Match(line);
            if (!m.Success) continue;
            var time = m.Groups[1].Value;
            var msg = m.Groups[2].Value;
            s.LastLineTime = time;

            if (msg.StartsWith("FortiPlugin.Connect -> "))
            {
                var rest = msg["FortiPlugin.Connect -> ".Length..];
                var paren = rest.IndexOf(" (", StringComparison.Ordinal);
                s.Target = (paren >= 0 ? rest[..paren] : rest).Trim();
                s.Phase = "Connecting";
                s.AwaitingTwoFactor = false;
                s.LastError = "";
                continue;
            }

            if (msg.StartsWith("gateway asked for a second factor") ||
                msg.StartsWith("gateway requested a second factor"))
            {
                s.AwaitingTwoFactor = true;
                continue;
            }

            var up = TunnelUp.Match(msg);
            if (up.Success)
            {
                s.Phase = "Up";
                s.AwaitingTwoFactor = false;
                s.Ip = up.Groups[1].Value;
                s.Mtu = up.Groups[2].Value;
                s.Routes = up.Groups[3].Value.Trim();
                s.Mode = up.Groups[4].Success ? "split" : "full";
                s.Dns = up.Groups[5].Value.Trim();
                s.Suffix = up.Groups[6].Value.Trim();
                continue;
            }

            var hb = Heartbeat.Match(msg);
            if (hb.Success)
            {
                if (s.Phase != "Up") s.Phase = "Up";  // a heartbeat only beats under a live tunnel
                s.Sent = long.Parse(hb.Groups[1].Value);
                s.Received = long.Parse(hb.Groups[2].Value);
                s.IdleSeconds = int.Parse(hb.Groups[3].Value);
                continue;
            }

            if (msg.StartsWith("Connect refused: ") || msg.StartsWith("Connect failed: "))
            {
                s.Phase = "Failed";
                s.LastError = msg[(msg.IndexOf(':') + 1)..].Trim();
                continue;
            }
        }

        return s;
    }

    // ---- rendering ---------------------------------------------------------

    private static void Render(State s, string? path, double? bytesPerSec)
    {
        if (!Console.IsOutputRedirected)
        {
            try { Console.Clear(); } catch { /* redirected or dumb terminal */ }
        }

        Console.WriteLine("  VPNTunnelWiS - tunnel status");
        Console.WriteLine("  " + new string('-', 46));

        if (s.ReadError.Length > 0)
        {
            Line("state", "cannot read log", ConsoleColor.Red);
            Console.WriteLine("        " + s.ReadError);
            return;
        }

        var (label, colour) = s.Phase switch
        {
            "Up" when s.IdleSeconds >= 0 && HeartbeatStale(s) =>
                ("UP (no recent heartbeat - may be asleep)", ConsoleColor.Yellow),
            "Up" => ("UP", ConsoleColor.Green),
            "Connecting" when s.AwaitingTwoFactor => ("waiting for one-time code", ConsoleColor.Cyan),
            "Connecting" => ("connecting...", ConsoleColor.Cyan),
            "Failed" => ("FAILED", ConsoleColor.Red),
            _ => ("idle / not connected", ConsoleColor.Gray),
        };
        Line("state", label, colour);

        if (s.Target.Length > 0) Line("gateway", s.Target);

        if (s.Phase == "Up")
        {
            Line("assigned IP", s.Ip);
            Line("mode", s.Mode == "split"
                ? $"SPLIT tunnel - only these go through: {Dash(s.Routes)}"
                : "FULL tunnel - ALL traffic through the gateway",
                s.Mode == "split" ? ConsoleColor.Green : ConsoleColor.Yellow);
            Line("routes", Dash(s.Routes));
            Line("DNS", Dash(s.Dns) + (s.Suffix.Length > 0 ? $"   suffix: {s.Suffix}" : ""));
            Line("mtu", s.Mtu);

            var traffic = $"sent {Human(s.Sent)}   received {Human(s.Received)}";
            if (bytesPerSec is > 0) traffic += $"   (~{Human((long)bytesPerSec.Value)}/s in)";
            Line("traffic", traffic);

            if (s.IdleSeconds >= 0)
                Line("idle", $"{s.IdleSeconds}s since last packet");
        }

        if (s.Phase == "Failed" && s.LastError.Length > 0)
            Line("reason", s.LastError, ConsoleColor.Red);

        Console.WriteLine();
        Console.WriteLine($"  last log line at {Dash(s.LastLineTime)}" +
                          (path is null ? "" : "   (Ctrl+C to quit)"));
    }

    // The plugin beats every 10s while a tunnel is live. If the newest heartbeat says the
    // tunnel has been idle far longer than that, the container has most likely been
    // suspended -- which the plugin itself flags as the tunnel possibly being asleep.
    private static bool HeartbeatStale(State s) => s.IdleSeconds >= 40;

    private static void Line(string key, string value, ConsoleColor? colour = null)
    {
        Console.Write($"  {key,-13}: ");
        if (colour is { } c && !Console.IsOutputRedirected)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = c;
            Console.WriteLine(value);
            Console.ForegroundColor = prev;
        }
        else
        {
            Console.WriteLine(value);
        }
    }

    private static string Dash(string v) => string.IsNullOrWhiteSpace(v) ? "-" : v;

    private static string Human(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double n = bytes;
        var u = 0;
        while (n >= 1024 && u < units.Length - 1) { n /= 1024; u++; }
        return u == 0 ? $"{bytes} B" : $"{n:0.0} {units[u]}";
    }

    // ---- collect -----------------------------------------------------------

    private static int Collect(string? tempLog)
    {
        var files = new List<string>();
        if (tempLog is not null && File.Exists(tempLog)) files.Add(tempLog);

        // The register/server logs live in LocalState, a sibling of AC\Temp under the same
        // package folder. Best-effort: they only exist if the registration tool ever ran.
        foreach (var name in new[] { "register.log", "server.log" })
        {
            var f = FindLog("LocalState", name);
            if (f is not null && !files.Contains(f)) files.Add(f);
        }

        if (files.Count == 0)
        {
            Console.WriteLine("No logs found to collect. Connect the VPN once first.");
            return 1;
        }

        var outPath = Path.Combine(Directory.GetCurrentDirectory(),
            $"forti-logs-{DateTime.Now:yyyyMMdd-HHmmss}.zip");

        Console.WriteLine("These logs record the gateway address, assigned IP, routes and packet");
        Console.WriteLine("counts. They contain no password. Only share them with someone you trust");
        Console.WriteLine("to see which network you connect to.");
        Console.WriteLine();

        try
        {
            using var zip = ZipFile.Open(outPath, ZipArchiveMode.Create);
            foreach (var f in files)
            {
                // Copy first so a log the plugin still holds open can be read.
                var tmp = Path.Combine(Path.GetTempPath(), Path.GetFileName(f));
                File.Copy(f, tmp, overwrite: true);
                zip.CreateEntryFromFile(tmp, Path.GetFileName(f));
                File.Delete(tmp);
                Console.WriteLine($"  + {Path.GetFileName(f)}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Could not write the zip: {ex.Message}");
            return 1;
        }

        Console.WriteLine();
        Console.WriteLine($"Wrote {outPath}");
        return 0;
    }
}
