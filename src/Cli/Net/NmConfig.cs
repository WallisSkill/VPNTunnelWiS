using System;
using System.Collections.Generic;
using System.Text;

namespace FortiVpn;

/// <summary>
/// Renders what the gateway pushed as one line of JSON on stdout, for the NetworkManager VPN
/// service to read and hand to NM over D-Bus.
///
/// This exists because the two integrations disagree about who owns the interface.
/// <see cref="RouteManager"/> configures it itself -- that is right for the standalone CLI,
/// where nothing else is watching. Under NetworkManager it is wrong: NM applies the address,
/// routes and DNS, tracks them as belonging to the connection, and tears them down when the
/// connection goes away. A plugin that also ran <c>ip route add</c> would be fighting it, and
/// the routes NM did not install are the ones it cannot clean up.
///
/// So in <c>--nm</c> mode the client's job stops at "the tun device exists and carries
/// packets", and this is how it says so. Hand-written rather than System.Text.Json because
/// the shape is six fixed keys and this keeps the reader on the other side obvious.
/// </summary>
internal static class NmConfig
{
    /// <param name="gatewayIp">Resolved IPv4 of the gateway. NM needs it to pin a host route
    /// to the real uplink in full-tunnel mode, or the TLS tunnel routes into itself.</param>
    public static string Render(string tunDev, TunnelConfig cfg, string gatewayIp, bool fullTunnel)
    {
        var sb = new StringBuilder();
        sb.Append('{');

        Str(sb, "tundev", tunDev).Append(',');
        Str(sb, "address", cfg.AssignedIpText).Append(',');

        // /32 with the routes carrying reachability, the way FortiOS models it: there is no
        // peer address and no subnet, only "this address is yours".
        Num(sb, "prefix", 32).Append(',');
        Num(sb, "mtu", cfg.Mtu).Append(',');
        Str(sb, "gateway", gatewayIp).Append(',');

        // never_default is the inverse of full tunnel: split mode must leave the machine's
        // own default route alone, full mode wants NM to replace it.
        sb.Append("\"never_default\":").Append(fullTunnel ? "false" : "true").Append(',');

        StrArray(sb, "dns", cfg.DnsServers).Append(',');
        StrArray(sb, "domains", cfg.DnsSuffixes).Append(',');

        // Only in split mode. In full mode NM installs the default itself and these would be
        // redundant entries it still has to track.
        sb.Append("\"routes\":[");
        if (!fullTunnel)
        {
            for (var i = 0; i < cfg.Routes.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append('{');
                Str(sb, "network", cfg.Routes[i].Network).Append(',');
                Num(sb, "prefix", cfg.Routes[i].PrefixLength);
                sb.Append('}');
            }
        }
        sb.Append(']');

        return sb.Append('}').ToString();
    }

    private static StringBuilder Str(StringBuilder sb, string key, string value) =>
        sb.Append('"').Append(key).Append("\":\"").Append(Escape(value)).Append('"');

    private static StringBuilder Num(StringBuilder sb, string key, long value) =>
        sb.Append('"').Append(key).Append("\":").Append(value.ToString(System.Globalization.CultureInfo.InvariantCulture));

    private static StringBuilder StrArray(StringBuilder sb, string key, List<string> values)
    {
        sb.Append('"').Append(key).Append("\":[");
        for (var i = 0; i < values.Count; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append('"').Append(Escape(values[i])).Append('"');
        }
        return sb.Append(']');
    }

    /// <summary>These values are addresses and DNS suffixes, but they come from the gateway,
    /// so they are escaped rather than trusted to be tame.</summary>
    private static string Escape(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (c == '"' || c == '\\') sb.Append('\\').Append(c);
            else if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
