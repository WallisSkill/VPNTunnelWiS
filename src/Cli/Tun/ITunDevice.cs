using System;

namespace FortiVpn;

/// <summary>
/// A layer-3 tunnel interface: raw IPv4 packets in and out, nothing else. The concrete
/// devices (<see cref="LinuxTun"/>, <see cref="MacTun"/>) hide the per-OS ceremony of
/// opening the interface and, on macOS, the 4-byte address-family prefix utun wraps every
/// packet in. Callers only ever see bare IP packets.
/// </summary>
internal interface ITunDevice : IDisposable
{
    /// <summary>The kernel-assigned interface name, e.g. <c>tun0</c> or <c>utun4</c>.</summary>
    string Name { get; }

    /// <summary>
    /// Blocks until one IP packet arrives, copies it into <paramref name="buffer"/> and
    /// returns its length. Returns 0 when the device has been closed.
    /// </summary>
    int Read(byte[] buffer);

    /// <summary>Writes one IP packet to the interface.</summary>
    void Write(ReadOnlySpan<byte> packet);
}

internal static class TunFactory
{
    /// <summary>Opens the right tun device for the running OS. Throws on Windows -- the
    /// plugin is the Windows story; this client is for macOS and Linux.</summary>
    public static ITunDevice Open()
    {
        if (OperatingSystem.IsLinux()) return new LinuxTun();
        if (OperatingSystem.IsMacOS()) return new MacTun();
        throw new PlatformNotSupportedException(
            "This client targets macOS and Linux. On Windows, install the VPN Platform plugin instead.");
    }
}
