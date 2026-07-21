using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;

namespace FortiVpn;

/// <summary>
/// Framing for PPP carried over the FortiOS TLS tunnel.
///
/// This is NOT async-HDLC. openfortivpn only speaks HDLC on the pty side, where it
/// talks to a real pppd; before anything reaches the socket it decodes the HDLC away
/// and prepends a 6-byte Fortinet header instead (see io.c, ssl_read/ssl_write):
///
///     [0..1] total length, big-endian, equal to 6 + len
///     [2..3] magic 0x5050
///     [4..5] len, the payload length
///     [6..]  payload: a 2-byte PPP protocol id followed by the packet body
///
/// There is no FCS and no byte stuffing. The address/control pair (FF 03) is absent
/// too -- the payload starts straight at the protocol id.
/// </summary>
internal static class FortiFrame
{
    public const ushort Magic = 0x5050;
    public const int HeaderSize = 6;

    public static byte[] Frame(ushort protocol, ReadOnlySpan<byte> body)
    {
        var len = 2 + body.Length;
        var buf = new byte[HeaderSize + len];
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(0), (ushort)(HeaderSize + len));
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(2), Magic);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(4), (ushort)len);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(6), protocol);
        body.CopyTo(buf.AsSpan(8));
        return buf;
    }

    /// <summary>
    /// Pulls every complete packet out of <paramref name="buffer"/>, removing what it
    /// consumed and leaving any partial tail in place.
    /// </summary>
    /// <param name="error">
    /// Set when the stream stops making sense: a bad magic means we are no longer
    /// looking at tunnel data, and there is no way to resynchronise, so the caller
    /// should give up rather than keep reading.
    /// </param>
    public static List<(ushort Protocol, byte[] Body)> Deframe(List<byte> buffer, out string? error)
    {
        error = null;
        var frames = new List<(ushort, byte[])>();

        while (buffer.Count >= HeaderSize)
        {
            var head = buffer.GetRange(0, HeaderSize).ToArray();

            // A gateway that allows web mode but not tunnel mode answers with a plain
            // HTTP error here instead of a packet, which is worth naming precisely.
            if (head[0] == 'H' && head[1] == 'T' && head[2] == 'T' && head[3] == 'P')
            {
                error = "the gateway returned HTTP instead of a packet -- tunnel mode may be disabled for this account";
                return frames;
            }

            var total = BinaryPrimitives.ReadUInt16BigEndian(head.AsSpan(0));
            var magic = BinaryPrimitives.ReadUInt16BigEndian(head.AsSpan(2));
            var size = BinaryPrimitives.ReadUInt16BigEndian(head.AsSpan(4));

            if (magic != Magic || total < 7 || total - HeaderSize != size)
            {
                error = $"header sai: total={total} magic=0x{magic:X4} size={size}";
                return frames;
            }

            if (buffer.Count < HeaderSize + size) break;      // packet still arriving

            var payload = buffer.GetRange(HeaderSize, size).ToArray();
            buffer.RemoveRange(0, HeaderSize + size);

            if (size >= 2)
                frames.Add((BinaryPrimitives.ReadUInt16BigEndian(payload), payload[2..]));
        }

        return frames;
    }
}

/// <summary>A PPP control packet: code, identifier and a list of TLV options.</summary>
internal sealed record CtrlPacket(byte Code, byte Id, byte[] Data)
{
    public static CtrlPacket? Parse(byte[] body)
    {
        if (body.Length < 4) return null;
        var len = BinaryPrimitives.ReadUInt16BigEndian(body.AsSpan(2));
        if (len < 4 || len > body.Length) return null;
        return new CtrlPacket(body[0], body[1], body[4..len]);
    }

    public byte[] Serialize()
    {
        var buf = new byte[4 + Data.Length];
        buf[0] = Code;
        buf[1] = Id;
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(2), (ushort)buf.Length);
        Data.CopyTo(buf, 4);
        return buf;
    }

    /// <summary>Splits the option area into (type, value) pairs. Malformed tails are ignored.</summary>
    public List<(byte Type, byte[] Value)> Options()
    {
        var opts = new List<(byte, byte[])>();
        var i = 0;
        while (i + 2 <= Data.Length)
        {
            var type = Data[i];
            var len = Data[i + 1];
            if (len < 2 || i + len > Data.Length) break;
            opts.Add((type, Data[(i + 2)..(i + len)]));
            i += len;
        }
        return opts;
    }

    public string CodeName => Code switch
    {
        1 => "Configure-Request", 2 => "Configure-Ack", 3 => "Configure-Nak",
        4 => "Configure-Reject", 5 => "Terminate-Request", 6 => "Terminate-Ack",
        7 => "Code-Reject", 8 => "Protocol-Reject", 9 => "Echo-Request",
        10 => "Echo-Reply", 11 => "Discard-Request", _ => $"code {Code}",
    };
}

internal static class Proto
{
    public const ushort Lcp = 0xC021;
    public const ushort Ipcp = 0x8021;
    public const ushort Pap = 0xC023;
    public const ushort Chap = 0xC223;
    public const ushort Ipv4 = 0x0021;

    public static string Name(ushort p) => p switch
    {
        Lcp => "LCP", Ipcp => "IPCP", Pap => "PAP",
        Chap => "CHAP", Ipv4 => "IPv4", _ => $"0x{p:X4}",
    };
}

internal static class Opt
{
    /// <summary>Builds a TLV option: type, total length, value.</summary>
    public static byte[] Tlv(byte type, params byte[] value)
    {
        var buf = new byte[2 + value.Length];
        buf[0] = type;
        buf[1] = (byte)buf.Length;
        value.CopyTo(buf, 2);
        return buf;
    }

    public static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    // LCP option types
    public const byte Mru = 1;
    public const byte Accm = 2;
    public const byte AuthProtocol = 3;
    public const byte MagicNumber = 5;

    // IPCP option types
    public const byte IpAddress = 3;
    public const byte PrimaryDns = 129;
    public const byte SecondaryDns = 131;

    public static string LcpName(byte t) => t switch
    {
        Mru => "MRU", Accm => "ACCM", AuthProtocol => "Auth-Protocol",
        MagicNumber => "Magic-Number", 7 => "PFC", 8 => "ACFC", _ => $"opt {t}",
    };

    public static string IpcpName(byte t) => t switch
    {
        IpAddress => "IP-Address", PrimaryDns => "Primary-DNS",
        SecondaryDns => "Secondary-DNS", 130 => "Primary-NBNS",
        132 => "Secondary-NBNS", _ => $"opt {t}",
    };

    public static string Describe(ushort proto, byte type, byte[] value)
    {
        var name = proto == Proto.Lcp ? LcpName(type) : IpcpName(type);
        var shown = value.Length == 4 && proto == Proto.Ipcp
            ? string.Join(".", value)
            : value.Length == 2
                ? BinaryPrimitives.ReadUInt16BigEndian(value).ToString()
                : Convert.ToHexString(value);
        return $"{name}={shown}";
    }
}
