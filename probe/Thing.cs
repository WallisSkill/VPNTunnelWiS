using Windows.Networking.Vpn;

namespace Probe
{
    // Minimal WinRT-authorable class implementing the same interface the real
    // plugin needs, purely to find out whether CsWinRT emits a .winmd here.
    public sealed class Thing : IVpnPlugIn
    {
        public void Connect(VpnChannel channel) { }
        public void Disconnect(VpnChannel channel) { }
        public void GetKeepAlivePayload(VpnChannel channel, out VpnPacketBuffer keepAlivePacket) { keepAlivePacket = null!; }
        public void Encapsulate(VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapsulatedPackets) { }
        public void Decapsulate(VpnChannel channel, VpnPacketBuffer encapBuffer, VpnPacketBufferList decapsulatedPackets, VpnPacketBufferList controlPacketsToSend) { }
    }
}
