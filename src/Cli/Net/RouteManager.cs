using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace FortiVpn;

/// <summary>
/// Brings the tunnel interface up and installs addressing, MTU, routes and DNS by shelling
/// out to the platform tools -- <c>ip</c> on Linux, <c>ifconfig</c>/<c>route</c> on macOS --
/// the same approach openfortivpn takes when it is not driving pppd's own route logic.
///
/// Routes bound to the tun interface disappear on their own when the interface goes away, so
/// teardown only has to undo the two things that outlive it: the host route that pins the
/// gateway to the real uplink (full-tunnel mode) and any DNS change.
/// </summary>
internal sealed class RouteManager
{
    private readonly Action<string> _log;
    private readonly List<string[]> _undo = new();
    private string? _dnsBackup;   // Linux: saved /etc/resolv.conf contents

    public RouteManager(Action<string> log) => _log = log;

    private static int Run(string file, params string[] args)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEnd();
        p.StandardError.ReadToEnd();
        p.WaitForExit();
        LastStdout = stdout;
        return p.ExitCode;
    }

    private static string LastStdout = "";

    private void Do(string file, params string[] args)
    {
        var code = Run(file, args);
        _log($"  $ {file} {string.Join(' ', args)}" + (code == 0 ? "" : $"   (exit {code})"));
    }

    /// <param name="gatewayIp">The gateway's resolved IPv4, pinned to the real uplink so the
    /// TLS tunnel itself does not get routed into the tunnel in full-tunnel mode.</param>
    public void Configure(ITunDevice tun, TunnelConfig cfg, string gatewayIp, bool fullTunnel)
    {
        if (OperatingSystem.IsLinux()) ConfigureLinux(tun, cfg, gatewayIp, fullTunnel);
        else if (OperatingSystem.IsMacOS()) ConfigureMac(tun, cfg, gatewayIp, fullTunnel);
        else throw new PlatformNotSupportedException();
    }

    // ---- Linux -------------------------------------------------------------

    private void ConfigureLinux(ITunDevice tun, TunnelConfig cfg, string gatewayIp, bool fullTunnel)
    {
        var dev = tun.Name;
        var ip = cfg.AssignedIpText;

        Do("ip", "link", "set", "dev", dev, "up");
        Do("ip", "link", "set", "dev", dev, "mtu", cfg.Mtu.ToString());
        Do("ip", "addr", "add", $"{ip}/32", "dev", dev);

        if (fullTunnel)
        {
            var (gwDev, gwVia) = LinuxDefaultRoute();
            if (gwVia is not null)
            {
                // Pin the gateway to the existing uplink so the encrypted tunnel does not
                // recurse into itself, then take the default with the 0/1 + 128/1 pair, which
                // out-specifics the real default without deleting it.
                Do("ip", "route", "add", $"{gatewayIp}/32", "via", gwVia, "dev", gwDev!);
                _undo.Add(new[] { "ip", "route", "del", $"{gatewayIp}/32" });
            }
            Do("ip", "route", "add", "0.0.0.0/1", "dev", dev);
            Do("ip", "route", "add", "128.0.0.0/1", "dev", dev);
        }
        else
        {
            foreach (var (net, prefix) in cfg.Routes)
                Do("ip", "route", "add", $"{net}/{prefix}", "dev", dev);
        }

        ConfigureLinuxDns(cfg);
    }

    private (string? Dev, string? Via) LinuxDefaultRoute()
    {
        if (Run("ip", "route", "show", "default") != 0) return (null, null);
        // "default via 192.168.1.1 dev eth0 ..."
        var parts = LastStdout.Split(new[] { ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        string? via = null, dev = null;
        for (var i = 0; i < parts.Length - 1; i++)
        {
            if (parts[i] == "via") via = parts[i + 1];
            if (parts[i] == "dev") dev = parts[i + 1];
        }
        return (dev, via);
    }

    private void ConfigureLinuxDns(TunnelConfig cfg)
    {
        if (cfg.DnsServers.Count == 0) return;
        try
        {
            // Plainest reliable path: replace /etc/resolv.conf and restore on teardown. Boxes
            // running systemd-resolved or resolvconf may reassert their own; that is documented.
            const string path = "/etc/resolv.conf";
            _dnsBackup = System.IO.File.Exists(path) ? System.IO.File.ReadAllText(path) : null;
            var lines = cfg.DnsServers.Select(s => $"nameserver {s}").ToList();
            if (cfg.DnsSuffixes.Count > 0) lines.Insert(0, "search " + string.Join(' ', cfg.DnsSuffixes));
            System.IO.File.WriteAllText(path, string.Join('\n', lines) + "\n");
            _log($"  DNS -> {string.Join(",", cfg.DnsServers)} (backed up {path})");
        }
        catch (Exception e)
        {
            _log($"  DNS not set automatically ({e.Message}); set it by hand if names do not resolve");
        }
    }

    // ---- macOS -------------------------------------------------------------

    private void ConfigureMac(ITunDevice tun, TunnelConfig cfg, string gatewayIp, bool fullTunnel)
    {
        var dev = tun.Name;
        var ip = cfg.AssignedIpText;

        // Point-to-point utun: local and remote both the assigned address is what FortiOS
        // expects (there is no distinct peer address in the SSL-VPN model).
        Do("ifconfig", dev, "inet", ip, ip, "mtu", cfg.Mtu.ToString(), "up");

        if (fullTunnel)
        {
            var gwVia = MacDefaultGateway();
            if (gwVia is not null)
            {
                Do("route", "add", "-host", gatewayIp, gwVia);
                _undo.Add(new[] { "route", "delete", "-host", gatewayIp });
            }
            Do("route", "add", "-net", "0.0.0.0/1", "-interface", dev);
            Do("route", "add", "-net", "128.0.0.0/1", "-interface", dev);
            _undo.Add(new[] { "route", "delete", "-net", "0.0.0.0/1", "-interface", dev });
            _undo.Add(new[] { "route", "delete", "-net", "128.0.0.0/1", "-interface", dev });
        }
        else
        {
            foreach (var (net, prefix) in cfg.Routes)
                Do("route", "add", "-net", $"{net}/{prefix}", "-interface", dev);
        }

        if (cfg.DnsServers.Count > 0)
            _log($"  DNS: set manually if needed -- " +
                 $"sudo networksetup -setdnsservers Wi-Fi {string.Join(' ', cfg.DnsServers)}");
    }

    private string? MacDefaultGateway()
    {
        if (Run("route", "-n", "get", "default") != 0) return null;
        foreach (var line in LastStdout.Split('\n'))
        {
            var t = line.Trim();
            if (t.StartsWith("gateway:")) return t.Substring("gateway:".Length).Trim();
        }
        return null;
    }

    // ---- teardown ----------------------------------------------------------

    public void Teardown()
    {
        foreach (var cmd in Enumerable.Reverse(_undo).ToList())
            Do(cmd[0], cmd.Skip(1).ToArray());

        if (_dnsBackup is not null)
        {
            try { System.IO.File.WriteAllText("/etc/resolv.conf", _dnsBackup); _log("  DNS restored"); }
            catch (Exception e) { _log($"  could not restore /etc/resolv.conf ({e.Message})"); }
        }
    }
}
