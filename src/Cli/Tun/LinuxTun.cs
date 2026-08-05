using System;
using System.Runtime.InteropServices;

namespace FortiVpn;

/// <summary>
/// A Linux TUN interface via <c>/dev/net/tun</c>.
///
/// Open the clone device, then <c>ioctl(TUNSETIFF)</c> with IFF_TUN|IFF_NO_PI to turn it
/// into a named layer-3 interface with no 4-byte packet-info prefix -- so what we read and
/// write is a bare IP packet, matching the FortiOS tunnel payload exactly. The kernel fills
/// the real name (tun0, tun1, ...) back into the request, which is what callers get.
///
/// Opening the device and, later, bringing the interface up and adding routes all need
/// CAP_NET_ADMIN, which in practice means running under sudo. There is no unprivileged
/// path on Linux; that trade is inherent to owning a tunnel interface here.
/// </summary>
internal sealed class LinuxTun : ITunDevice
{
    private const int O_RDWR = 0x0002;

    // From <linux/if_tun.h> and <linux/if.h>.
    private const short IFF_TUN = 0x0001;
    private const short IFF_NO_PI = 0x1000;

    // _IOW('T', 202, int) == 0x400454ca. The 'T' ioctl space, direction write, 4-byte arg.
    private const ulong TUNSETIFF = 0x400454ca;

    private const int IFNAMSIZ = 16;

    private readonly int _fd;
    public string Name { get; }

    [DllImport("libc", SetLastError = true)]
    private static extern int open(string path, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", SetLastError = true, EntryPoint = "ioctl")]
    private static extern int ioctl(int fd, ulong request, byte[] argp);

    [DllImport("libc", SetLastError = true)]
    private static extern nint read(int fd, byte[] buf, nuint count);

    [DllImport("libc", SetLastError = true)]
    private static extern nint write(int fd, byte[] buf, nuint count);

    public LinuxTun()
    {
        _fd = open("/dev/net/tun", O_RDWR);
        if (_fd < 0)
            throw new InvalidOperationException(
                $"cannot open /dev/net/tun (errno {Marshal.GetLastPInvokeError()}) -- run with sudo");

        // struct ifreq: char ifr_name[IFNAMSIZ]; then a union whose first member here is
        // short ifr_flags. 40 bytes is the whole struct on 64-bit Linux; we only touch the
        // name and the flags word at offset IFNAMSIZ.
        var ifr = new byte[40];
        var flags = (short)(IFF_TUN | IFF_NO_PI);
        ifr[IFNAMSIZ] = (byte)(flags & 0xff);
        ifr[IFNAMSIZ + 1] = (byte)((flags >> 8) & 0xff);

        if (ioctl(_fd, TUNSETIFF, ifr) < 0)
        {
            var err = Marshal.GetLastPInvokeError();
            close(_fd);
            throw new InvalidOperationException($"TUNSETIFF failed (errno {err})");
        }

        var end = Array.IndexOf(ifr, (byte)0, 0, IFNAMSIZ);
        if (end < 0) end = IFNAMSIZ;
        Name = System.Text.Encoding.ASCII.GetString(ifr, 0, end);
    }

    public int Read(byte[] buffer)
    {
        var n = read(_fd, buffer, (nuint)buffer.Length);
        return n < 0 ? 0 : (int)n;
    }

    public void Write(ReadOnlySpan<byte> packet)
    {
        // The BCL P/Invoke wants an array; copy the span into a right-sized buffer. Packets
        // are MTU-bounded (~1354), so this allocation is small and short-lived.
        var buf = packet.ToArray();
        _ = write(_fd, buf, (nuint)buf.Length);
    }

    public void Dispose()
    {
        if (_fd >= 0) close(_fd);
    }
}
