using System;
using System.Runtime.InteropServices;
using System.Text;

namespace FortiVpn;

/// <summary>
/// A macOS utun interface.
///
/// There is no /dev/net/tun on macOS. A utun is opened as a kernel-control socket: create
/// a PF_SYSTEM / SYSPROTO_CONTROL socket, resolve the control id of "com.apple.net.utun_control"
/// with ioctl(CTLIOCGINFO), then connect() a sockaddr_ctl to it. sc_unit = 0 lets the kernel
/// pick the lowest free utunN; the name is read back with getsockopt(UTUN_OPT_IFNAME).
///
/// Unlike Linux IFF_NO_PI, a utun ALWAYS prefixes every packet with a 4-byte address family
/// in network byte order (AF_INET = 2 for IPv4). This class adds that header on write and
/// strips it on read, so callers deal only in bare IP packets -- the same shape the FortiOS
/// tunnel carries. Opening the socket and configuring the interface need root (sudo).
/// </summary>
internal sealed class MacTun : ITunDevice
{
    private const int PF_SYSTEM = 32;
    private const int SOCK_DGRAM = 2;
    private const int SYSPROTO_CONTROL = 2;

    private const int AF_SYSTEM = 32;
    private const int AF_SYS_CONTROL = 2;
    private const uint AF_INET = 2;

    // _IOWR('N', 3, struct ctl_info), ctl_info being 100 bytes -> 0xc0644e03.
    private const ulong CTLIOCGINFO = 0xc0644e03;

    private const int UTUN_OPT_IFNAME = 2;

    private const string UTUN_CONTROL_NAME = "com.apple.net.utun_control";

    private readonly int _fd;
    public string Name { get; }

    [DllImport("libc", SetLastError = true)]
    private static extern int socket(int domain, int type, int protocol);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", SetLastError = true, EntryPoint = "ioctl")]
    private static extern int ioctl(int fd, ulong request, byte[] argp);

    [DllImport("libc", SetLastError = true)]
    private static extern int connect(int fd, byte[] addr, uint addrlen);

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(int fd, int level, int optname, byte[] optval, ref uint optlen);

    [DllImport("libc", SetLastError = true)]
    private static extern nint read(int fd, byte[] buf, nuint count);

    [DllImport("libc", SetLastError = true)]
    private static extern nint write(int fd, byte[] buf, nuint count);

    public MacTun()
    {
        _fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (_fd < 0)
            throw new InvalidOperationException(
                $"cannot open a system-control socket (errno {Marshal.GetLastPInvokeError()}) -- run with sudo");

        // struct ctl_info { uint32_t ctl_id; char ctl_name[96]; } == 100 bytes.
        var info = new byte[100];
        var nameBytes = Encoding.ASCII.GetBytes(UTUN_CONTROL_NAME);
        Array.Copy(nameBytes, 0, info, 4, nameBytes.Length);
        if (ioctl(_fd, CTLIOCGINFO, info) < 0)
        {
            var err = Marshal.GetLastPInvokeError();
            close(_fd);
            throw new InvalidOperationException($"CTLIOCGINFO failed (errno {err})");
        }
        var ctlId = BitConverter.ToUInt32(info, 0);

        // struct sockaddr_ctl { u_char sc_len; u_char sc_family; u_int16_t ss_sysaddr;
        //   u_int32_t sc_id; u_int32_t sc_unit; u_int32_t sc_reserved[5]; } == 32 bytes.
        var sa = new byte[32];
        sa[0] = 32;                       // sc_len
        sa[1] = (byte)AF_SYSTEM;          // sc_family
        sa[2] = (byte)AF_SYS_CONTROL;     // ss_sysaddr, low byte (host order)
        sa[3] = 0;
        BitConverter.GetBytes(ctlId).CopyTo(sa, 4);   // sc_id
        BitConverter.GetBytes(0u).CopyTo(sa, 8);      // sc_unit = 0 -> kernel picks utunN

        if (connect(_fd, sa, 32) < 0)
        {
            var err = Marshal.GetLastPInvokeError();
            close(_fd);
            throw new InvalidOperationException($"connect(utun) failed (errno {err})");
        }

        var nameBuf = new byte[64];
        uint len = (uint)nameBuf.Length;
        if (getsockopt(_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, nameBuf, ref len) < 0)
        {
            var err = Marshal.GetLastPInvokeError();
            close(_fd);
            throw new InvalidOperationException($"UTUN_OPT_IFNAME failed (errno {err})");
        }
        // len includes the trailing NUL.
        var end = (int)(len > 0 ? len - 1 : 0);
        Name = Encoding.ASCII.GetString(nameBuf, 0, end);
    }

    public int Read(byte[] buffer)
    {
        // Read into a scratch buffer with room for the 4-byte AF header, then hand back
        // just the IP packet.
        var scratch = new byte[buffer.Length + 4];
        var n = read(_fd, scratch, (nuint)scratch.Length);
        if (n <= 4) return 0;
        var packetLen = (int)n - 4;
        Array.Copy(scratch, 4, buffer, 0, packetLen);
        return packetLen;
    }

    public void Write(ReadOnlySpan<byte> packet)
    {
        var buf = new byte[packet.Length + 4];
        // AF_INET in network byte order: 0x00 00 00 02.
        buf[3] = (byte)AF_INET;
        packet.CopyTo(buf.AsSpan(4));
        _ = write(_fd, buf, (nuint)buf.Length);
    }

    public void Dispose()
    {
        if (_fd >= 0) close(_fd);
    }
}
