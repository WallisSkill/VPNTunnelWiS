using FortiVpn;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.ApplicationModel.Background;
using Windows.Networking;
using Windows.Networking.Vpn;

namespace FortiVpnPlugin
{
    /// <summary>
    /// FortiOS SSL-VPN provider for the Windows VPN platform.
    ///
    /// The division of labour is deliberate. <see cref="Connect"/> carries the entire
    /// stateful part -- TLS, login, allocation, LCP and IPCP -- and only then hands the
    /// socket to Windows. After that the platform owns the reads and writes, and
    /// <see cref="Encapsulate"/> / <see cref="Decapsulate"/> are purely mechanical:
    /// add or strip the 6-byte Fortinet header around an IPv4 packet. There is no HDLC
    /// and no FCS anywhere on this path.
    /// </summary>
    public sealed class FortiPlugin : IVpnPlugIn, IBackgroundTask
    {
        /// <summary>
        /// How the platform actually reaches this class. It is activated as the background
        /// task named by the manifest EntryPoint, in the app's own host process, and only
        /// becomes a VPN plugin once the trigger details are handed back to
        /// <see cref="VpnChannel.ProcessEventAsync"/>. A class implementing only
        /// <see cref="IVpnPlugIn"/> is answered with E_NOINTERFACE and never gets this far.
        /// </summary>
        public void Run(IBackgroundTaskInstance taskInstance)
        {
            // Two lines an activation is nothing while a dial is being diagnosed and far too
            // much once a tunnel is up: the platform activates this per packet, thousands of
            // times a minute. The first few are what matter -- they show the dial -- and after
            // that one line every thousand is enough to prove activations are still arriving.
            var activation = System.Threading.Interlocked.Increment(ref _activations);

            // Loud again once the data plane goes quiet, because the fifteen seconds a
            // disconnect takes are fifteen seconds this log could not see: traffic stops the
            // moment the user clicks, the activation counter is long past eight by then, and
            // every activation the platform delivers during the teardown fell in the gap
            // between "first eight" and "every thousandth". Whether the platform activates
            // this task at all while Windows tears the tunnel down is the one fact that says
            // if the wait is ours to fix, and it has never once been recorded.
            //
            // Quiet is the right trigger rather than a flag, because nothing tells the plugin
            // a disconnect has started -- no Disconnect call and no cancel has ever arrived.
            // Silence is the only signal available. It costs a handful of lines on a merely
            // idle tunnel and nothing at all on a busy one.
            var loud = activation <= 8 || SinceLastPacket >= TimeSpan.FromSeconds(2);
            if (loud) Trace($"IBackgroundTask.Run obj#{_instanceId} {taskInstance.TriggerDetails?.GetType().FullName ?? "<null>"} " +
                            $"(activation {activation}, idle={SinceLastPacket.TotalSeconds:0.0}s)");
            else if (activation % 1000 == 0) Trace($"activation {activation}");

            var activationState = new Activation(taskInstance.GetDeferral());

            // The cancel has to be answered by the activation it belongs to. Completing some
            // other instance's deferral leaves the cancelled one outstanding, and a cancel
            // that goes unanswered does not just end the task -- BrokerInfrastructure event 6,
            // the host process terminated, RAS 829, the live tunnel gone with it.
            taskInstance.Canceled += (_, reason) =>
            {
                // The state alongside the reason, because this is the one line that can say
                // what a disconnect actually does to this plugin. If a cancel arrives here
                // with the tunnel still live and the session still open, then the platform
                // is tearing the tunnel down without ever calling Disconnect -- and the wait
                // the user sees is the platform's timeout, not our teardown.
                Trace($"background task cancelled: {reason} " +
                      $"(tunnelLive={_tunnelLive} session={(_session is null ? "none" : "open")} " +
                      $"sent={_sent} received={_received})");
                activationState.Finish();
            };

            try
            {
                // Canonical rather than this, because the platform builds a new FortiPlugin
                // for every activation -- obj#1, obj#2, obj#3, obj#4 in a single connect and
                // disconnect -- and the channel belongs to whichever object serviced Connect.
                // Handing ProcessEventAsync a stranger is the one anomaly that fits every
                // measurement: the disconnect event arrives, dispatch finds nothing to call,
                // Disconnect is never entered, and the platform waits out a fifteen second
                // timeout before tearing the tunnel down itself.
                //
                // Every field in this class is already static for the same reason, so passing
                // the first object costs nothing -- it carries no state the others lack.
                var canonical = System.Threading.Interlocked.CompareExchange(ref _canonical, this, null) ?? this;
                if (loud && !ReferenceEquals(canonical, this))
                    Trace($"  dispatching on obj#{canonical._instanceId} instead of obj#{_instanceId}");

                VpnChannel.ProcessEventAsync(canonical, taskInstance.TriggerDetails);
                // Logged on the way out as well as the way in. An activation that dispatches
                // nothing at all looks exactly like one that hung inside a handler unless the
                // return is recorded, and both have been seen here.
                if (loud) Trace("ProcessEventAsync returned");
            }
            catch (Exception ex)
            {
                Trace($"ProcessEventAsync failed: {ex}");
            }
            finally
            {
                // While a tunnel is up, one activation has to stay outstanding or the app
                // container is suspended and the tunnel dies with it -- measured directly:
                // every thread of the host in Wait/Suspended, CPU frozen, no heartbeat, and
                // ping across the tunnel at 100% loss while Windows still reported Connected.
                // Encapsulate cannot run in a suspended process, so outbound packets are never
                // framed and nothing ever comes back.
                //
                // But no single deferral can cover the tunnel either, and letting one be taken
                // away is worse than not holding it at all: the platform cancels a hold with
                // ExecutionTimeExceeded after about ninety seconds, and the channel never
                // carries traffic again afterwards. Measured across one host process --
                // sent=1874 received=1602 climbing steadily, then the cancel at 11:09:58, then
                // those two counters frozen at exactly those values for the next six minutes
                // while the heartbeat kept ticking. Every redial in that same process got a
                // tunnel that sent and received nothing, and the platform redialled on each
                // cancel, which is the connect-disconnect churn seen from the outside.
                //
                // So the hold rotates on its own clock, well inside the limit, and the
                // execution-time cancel is never reached. Releasing it makes the platform go
                // back to activating per packet, and the very next packet hands the hold to a
                // fresh activation with a fresh ninety seconds.
                // And the hold is only worth taking while the tunnel is actually carrying
                // something. Taking it through an idle spell is what produced the failure
                // this guard exists for: the container slept while owing a deferral, the
                // rotation timer slept with it, and the platform's ninety wall-clock seconds
                // ran out unattended -- ExecutionTimeExceeded, and with it a channel that
                // never carried another packet in that host process. An idle tunnel that
                // sleeps owing nothing gives up latency on the next outbound packet and
                // keeps the data path.
                if (!_tunnelLive || SinceLastPacket >= IdleBeforeSleep ||
                    System.Threading.Interlocked.CompareExchange(ref _hold, activationState, null) is not null)
                {
                    activationState.Finish();
                }
                else
                {
                    activationState.HoldUntilRotation();
                    if (loud) Trace("this activation is holding the container awake");
                }
            }
        }

        /// <summary>
        /// One activation's deferral, plus the guarantee that it is completed exactly once.
        /// It can be finished from three places -- the end of <see cref="Run"/>, the cancel
        /// handler, and <see cref="Disconnect"/> -- and completing a deferral twice throws.
        /// </summary>
        private sealed class Activation
        {
            private readonly BackgroundTaskDeferral _deferral;
            private System.Threading.Timer? _rotation;
            private int _finished;

            public Activation(BackgroundTaskDeferral deferral) => _deferral = deferral;

            /// <summary>
            /// Gives this hold a deadline of our own, comfortably inside the platform's. The
            /// measured cancel came at 89.7 seconds; going first at sixty means the plugin is
            /// always the one that let go, and <c>ExecutionTimeExceeded</c> -- which kills the
            /// channel's data path for the rest of the process -- never arrives.
            /// </summary>
            public void HoldUntilRotation()
            {
                System.Threading.Interlocked.Exchange(ref _heldSinceTicks, DateTime.UtcNow.Ticks);

                // Periodic and wall-clock, not a one-shot measured in process time. A
                // one-shot does not fire at all while the container is suspended, so a hold
                // taken shortly before a suspension sailed straight past the platform's
                // ninety seconds -- which *are* wall-clock -- and came back as
                // ExecutionTimeExceeded. Measured: hold taken 22:58:20, container asleep,
                // awake again 23:13:01, cancel 23:13:18.
                _rotation = new System.Threading.Timer(
                    _ => Review(), null, RotationCheck, RotationCheck);
            }

            /// <summary>
            /// Gives the hold up once it has run its wall-clock course, or once the data
            /// plane has gone quiet for <see cref="IdleBeforeSleep"/>.
            ///
            /// The idle half is the important one. Holding through an idle spell is what put
            /// the container to sleep *while owing a deferral*, and the platform cancels a
            /// hold it has waited ninety seconds for however asleep the holder was. Letting
            /// go first means an idle tunnel sleeps owing nothing: the next outbound packet
            /// wakes the container and the hold is taken again by whichever activation
            /// carries it. That costs latency on the first packet after a quiet spell and
            /// nothing else -- against ExecutionTimeExceeded, which takes the channel's data
            /// path down for the rest of the host process.
            /// </summary>
            private void Review()
            {
                var held = DateTime.UtcNow - new DateTime(
                    System.Threading.Interlocked.Read(ref _heldSinceTicks), DateTimeKind.Utc);

                var quiet = SinceLastPacket;
                if (quiet >= IdleBeforeSleep)
                {
                    Trace($"data plane quiet for {quiet.TotalSeconds:0}s, letting the container sleep");
                    Finish();
                    return;
                }

                if (held >= RotationInterval)
                {
                    Trace($"rotating the hold (held {held.TotalSeconds:0.0}s)");
                    Finish();
                }
            }

            /// <summary>UTC ticks at which this activation took the hold.</summary>
            private long _heldSinceTicks;

            public void Finish()
            {
                if (System.Threading.Interlocked.Exchange(ref _finished, 1) != 0) return;

                _rotation?.Dispose();

                // Stand down as the holder first, so the next activation can take the hold
                // rather than finding a completed deferral parked there.
                System.Threading.Interlocked.CompareExchange(ref _hold, null, this);
                try { _deferral.Complete(); }
                catch (Exception ex) { Trace($"completing the deferral failed: {ex.Message}"); }
            }
        }

        /// <summary>How long one activation keeps the container awake before handing over.</summary>
        private static readonly TimeSpan RotationInterval = TimeSpan.FromSeconds(60);

        /// <summary>
        /// How often a live hold re-reads the wall clock. Frequent because the check is the
        /// only thing standing between a suspension and ExecutionTimeExceeded, and it costs
        /// one comparison.
        /// </summary>
        private static readonly TimeSpan RotationCheck = TimeSpan.FromSeconds(1);

        /// <summary>
        /// How long the data plane may be silent before the hold is released and the
        /// container is allowed to sleep owing nothing. Well inside the platform's ninety
        /// seconds, so the decision to let go is always ours.
        ///
        /// Five rather than thirty because of what a disconnect looks like from in here. The
        /// plugin is never told about one -- no Disconnect call and no cancel has ever been
        /// logged -- so the only thing it does while Windows tears the tunnel down is hold a
        /// deferral the platform cannot collect. Measured: last packet out at 00:33:01,
        /// Settings still saying "Disconnecting" fifteen seconds later, the hold not released
        /// until 00:33:32. Traffic stops the moment the user clicks, so a short silence is
        /// the earliest reliable sign that the tunnel is going away.
        ///
        /// The cost is paid by a tunnel that is merely idle rather than closing: it sleeps
        /// sooner, and the next outbound packet waits for the container to be woken. That is
        /// latency on one packet, against fifteen seconds of staring at a dialog.
        /// </summary>
        private static readonly TimeSpan IdleBeforeSleep = TimeSpan.FromSeconds(5);

        /// <summary>
        /// UTC ticks of the last packet seen in either direction. Read from the rotation
        /// timer on another thread, so it moves through <see cref="System.Threading.Interlocked"/>.
        /// </summary>
        private static long _lastTrafficTicks;

        /// <summary>How long the data plane has been quiet.</summary>
        private static TimeSpan SinceLastPacket
            => DateTime.UtcNow - new DateTime(
                System.Threading.Interlocked.Read(ref _lastTrafficTicks), DateTimeKind.Utc);

        /// <summary>
        /// How long the courtesy logout of a replaced session gets. Short on purpose: it is
        /// an optimisation on the dial that follows it, and must never delay it noticeably.
        /// </summary>
        private static readonly TimeSpan LogoutTimeout = TimeSpan.FromSeconds(3);

        /// <summary>The activation currently keeping the app container out of suspension.</summary>
        private static Activation? _hold;

        /// <summary>Whether a tunnel is up and worth holding the container awake for.</summary>
        private static volatile bool _tunnelLive;

        /// <summary>Bytes a Fortinet frame adds to the IP packet it carries: the 6-byte
        /// header plus the 2-byte PPP protocol field.</summary>
        private const int FrameOverhead = FortiFrame.HeaderSize + 2;

        /// <summary>
        /// The port assumed when the profile names none. A string rather than an int because
        /// that is how it travels from here to the socket, and because ResolveServer compares
        /// against it to tell "the user typed a port" from "we guessed one".
        /// </summary>
        private const string DefaultPort = "443";

        /// <summary>
        /// How long the whole exchange -- TLS, login, allocation, PPP -- gets before it is
        /// called off. Without a bound, a gateway that completes the TLS handshake and then
        /// says nothing leaves this thread parked in a read for as long as the socket stays
        /// open, and the platform eventually reports a timeout with no reason attached.
        /// FortiOS goes quiet exactly like that once it starts throttling a source that has
        /// failed to log in several times, so the silent case is the one worth naming.
        /// </summary>
        private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(25);

        /// <summary>
        /// Whether the gateway turned down the credential used by the dial immediately
        /// before this one. Non-zero for exactly one dial: <see cref="FetchCredentials"/>
        /// consumes it.
        ///
        /// The platform answers <c>RequestCredentials</c> from its own cache unless the
        /// request is marked as a retry, and it caches whatever was typed even when the dial
        /// then failed. So one mistyped password gets replayed from the cache on every dial
        /// afterwards, the user is never asked again, and the correct password never reaches
        /// the gateway. Marking the next request as a retry is what drops the cached pair and
        /// puts the prompt back.
        ///
        /// Consumed rather than left standing, because "retry" is an instruction for one dial
        /// and it used to outlive the typo that set it. A profile that carries a username and
        /// password -- entered in Settings > Add VPN, kept because the profile has
        /// RememberCredentials -- is stored in that same cache, so a permanently armed retry
        /// flag threw it away on every dial and prompted for a pair Windows already had.
        /// That is the "SSL-VPN never lets me save my sign-in details" symptom: the details
        /// were saved, and this discarded them.
        ///
        /// Static because the platform builds a fresh plugin object for every event; an
        /// instance field would be forgotten between the failed dial and the next one. An int
        /// rather than a bool so it can be read and cleared in one interlocked step -- the
        /// platform dispatches Connect twice for the same dial.
        /// </summary>
        private static int _credentialRejected;

        /// <summary>
        /// Reassembly buffer for the inbound direction. The transport hands over whatever
        /// TLS records happened to arrive, so a Fortinet frame can be split across two
        /// Decapsulate calls, and several can arrive in one.
        /// </summary>
        /// Static, not per-instance: the platform activates a fresh plugin object for every
        /// background-task event, so a partial frame left by one Decapsulate would be thrown
        /// away before the next one ran.
        private static readonly List<byte> _rx = new();

        /// <summary>
        /// Diagnostics that survive. <see cref="VpnChannel.LogDiagnosticMessage"/> goes to
        /// the "Windows Networking Vpn Plugin Platform" channel, which cannot be enabled
        /// without administrator rights, so everything is also appended to a file inside
        /// the package's own temp folder.
        /// </summary>
        private static readonly object _logGate = new();

        /// <summary>
        /// Held open for the life of the process. Opening, writing and closing the file per
        /// line was affordable while one activation served the whole tunnel; it is not once
        /// the platform activates the plugin per packet, which it does at roughly two and a
        /// half thousand times a minute under real traffic.
        /// </summary>
        private static System.IO.StreamWriter? _logFile;

        private static void Trace(string message)
        {
            // The data path is multi-threaded, and two threads appending at once used to
            // lose both lines to a sharing violation -- which read as "Encapsulate is never
            // called" when in fact it was called and the evidence was thrown away.
            lock (_logGate)
            {
                try
                {
                    // FileShare.ReadWrite so the file can still be read while the tunnel runs.
                    _logFile ??= new System.IO.StreamWriter(
                        new System.IO.FileStream(
                            System.IO.Path.Combine(System.IO.Path.GetTempPath(), "forti-plugin.log"),
                            System.IO.FileMode.Append, System.IO.FileAccess.Write,
                            System.IO.FileShare.ReadWrite))
                    {
                        // Flushed per line on purpose: the interesting failures end with the
                        // process being killed, and a buffered tail would die with it.
                        AutoFlush = true,
                    };
                    _logFile.WriteLine($"{DateTime.Now:HH:mm:ss.fff} {message}");
                }
                catch
                {
                    // Logging must never be the reason a dial fails.
                }
            }
        }

        /// <summary>
        /// Where to dial, taken from the profile the user created rather than from this
        /// assembly. The package is a provider: anyone may point a connection of their own
        /// at any FortiGate, and hard-coding one gateway would silently dial the wrong one.
        ///
        /// Three places are tried because the address lands in a different one depending on
        /// how the connection was made, and each is read in its own try: they come straight
        /// off the profile and any one of them can throw on its own.
        /// </summary>
        private static ServerTarget ResolveServer(VpnChannel channel)
        {
            var cfg = channel.Configuration;

            // CustomField first: it is the plugin schema, so anything put there was put
            // there deliberately. A profile made in Settings leaves it empty.
            try
            {
                var custom = cfg?.CustomField;
                if (!string.IsNullOrWhiteSpace(custom))
                {
                    const string open = "<serverUrl>", close = "</serverUrl>";
                    var from = custom.IndexOf(open, StringComparison.OrdinalIgnoreCase);
                    var to = custom.IndexOf(close, StringComparison.OrdinalIgnoreCase);
                    if (from >= 0 && to > from)
                    {
                        var raw = custom[(from + open.Length)..to];
                        var parsed = ParseServer(raw);
                        if (parsed is not null)
                            return new ServerTarget(parsed.Value.Host, parsed.Value.Port,
                                                    SplitFromAddress(raw));
                    }
                }
            }
            catch (Exception ex)
            {
                Trace($"CustomField unreadable: {ex.Message}");
            }

            // Then the host name list, which serves a profile whose address carries no port:
            // the port then has to come from ServerServiceName instead.
            //
            // It cannot serve one that does. The platform builds each element by calling
            // HostName(String) on the stored text, and HostName rejects a colon, so reading
            // the vector throws E_INVALIDARG ("The parameter is incorrect. hostName") before
            // a single element is handed over. That is not recoverable from here -- which is
            // why the address has to be typed as a URI, and why ServerUris below is the
            // branch that actually runs for this gateway.
            try
            {
                foreach (var name in cfg?.ServerHostNameList ?? [])
                {
                    // Both logged, not just the one used: which of the two keeps the port is
                    // the whole question here, and a log that only shows the winner cannot
                    // answer it the next time a profile arrives in some third shape.
                    Trace($"ServerHostNameList: canonical='{name?.CanonicalName}' " +
                          $"display='{name?.DisplayName}'");

                    var text = string.IsNullOrWhiteSpace(name?.CanonicalName)
                        ? name?.DisplayName
                        : name.CanonicalName;
                    if (string.IsNullOrWhiteSpace(text)) continue;

                    var parsed = ParseServer(text);
                    if (parsed is null) continue;
                    var split = SplitFromAddress(text);

                    // A port typed as part of the address is already in there. Only when it
                    // is not does ServerServiceName get a say -- and it usually has nothing
                    // to say, reading back as "0" for a profile that named no service.
                    if (parsed.Value.Port != DefaultPort)
                        return new ServerTarget(parsed.Value.Host, parsed.Value.Port, split);

                    var service = cfg?.ServerServiceName;
                    Trace($"ServerServiceName: '{service}'");
                    if (!string.IsNullOrWhiteSpace(service) && service != "0" &&
                        int.TryParse(service, out var port) && port is > 0 and <= 65535)
                    {
                        return new ServerTarget(parsed.Value.Host, service, split);
                    }

                    return new ServerTarget(parsed.Value.Host, parsed.Value.Port, split);
                }
            }
            catch (Exception ex)
            {
                Trace($"ServerHostNameList unreadable: {ex.Message}");
            }

            // Last in order, first in practice: this is the branch that carries a gateway
            // with a port on it. "host:port" typed on its own does not reach here intact --
            // System.Uri reads the host as a scheme and throws "The URI scheme is not
            // valid." -- so the address has to be typed as "https://host:port", which both
            // Settings and Uri accept. Reading the vector throws outright when any element
            // fails to parse, so nothing can be salvaged element by element.
            try
            {
                var uri = cfg?.ServerUris?.FirstOrDefault();
                if (uri is not null && !string.IsNullOrEmpty(uri.Host))
                {
                    // Port is -1 when the profile names no port, and FortiOS portals are
                    // https, so 443 is the right default rather than 80.
                    var port = uri.Port > 0 ? uri.Port.ToString() : DefaultPort;
                    // A "/split" left on the path is the one place a split-tunnel request can
                    // ride in: Uri keeps it as AbsolutePath, clear of the host and port.
                    return new ServerTarget(uri.Host, port, SplitFromAddress(uri.AbsolutePath));
                }
            }
            catch (Exception ex)
            {
                Trace($"ServerUris unreadable: {ex.Message}");
            }

            // No built-in gateway to fall back on, deliberately: the address belongs to
            // whoever installs this, not to the plugin. Failing here names the one thing the
            // user can actually fix.
            // Naming the exact form is the whole point of this message: "host:port" is the
            // obvious thing to type, it is what Settings accepts without complaint, and it
            // is unreadable from in here.
            throw new InvalidOperationException(
                "This connection has no usable gateway address. Edit it in Settings > " +
                "Network & internet > VPN and enter the server as a full URL with the " +
                "port, like https://vpn.example.com:8080 -- an address written without " +
                "https:// cannot be read back.");
        }

        /// <summary>
        /// Splits what the user typed into Settings. Accepts "host", "host:port" and a
        /// full "https://host:port/", because all three reach here depending on how the
        /// connection was created.
        /// </summary>
        private static (string Host, string Port)? ParseServer(string text)
        {
            text = text.Trim();

            var scheme = text.IndexOf("://", StringComparison.Ordinal);
            if (scheme >= 0) text = text[(scheme + 3)..];
            var slash = text.IndexOf('/');
            if (slash >= 0) text = text[..slash];
            if (text.Length == 0) return null;

            // Last colon, not first: an IPv6 literal is full of them, and only the one
            // after the closing bracket separates the port.
            var colon = text.LastIndexOf(':');
            if (colon > 0 && colon > text.LastIndexOf(']') &&
                int.TryParse(text[(colon + 1)..], out var port) && port is > 0 and <= 65535)
            {
                return (text[..colon].Trim('[', ']'), port.ToString());
            }

            return (text.Trim('[', ']'), DefaultPort);
        }

        /// <summary>
        /// One resolved gateway: where to dial, and -- when the profile address carried a
        /// <c>/split</c> -- which networks alone should go through the tunnel.
        /// <see cref="SplitRoutes"/> is null when there was no such directive, and Connect
        /// then routes whatever the gateway asks for (everything, for this one).
        /// </summary>
        private sealed record ServerTarget(string Host, string Port, List<VpnRoute>? SplitRoutes);

        /// <summary>
        /// The private IPv4 ranges a bare <c>/split</c> routes through the tunnel. Enough to
        /// reach machines on an office LAN -- remote desktop included -- while every public
        /// address stays on the physical adapter and the machine keeps its own internet.
        /// </summary>
        private static readonly (string Network, byte Prefix)[] PrivateRanges =
        {
            ("10.0.0.0", 8), ("172.16.0.0", 12), ("192.168.0.0", 16),
        };

        /// <summary>
        /// Finds a <c>/split</c> directive anywhere in the address the user typed and turns it
        /// into the list of networks to tunnel. Returns null when there is none, which leaves
        /// the tunnel carrying everything the gateway asks for.
        ///
        /// <c>/split</c> on its own means <see cref="PrivateRanges"/>. <c>/split=10.1.0.0/16</c>
        /// -- comma-separated, a bare address meaning a single /32 -- names exact networks
        /// instead. A token that is not an IPv4 network is dropped with a log line rather than
        /// thrown: a typo must not reach the platform, and it must not silently fall back to a
        /// full tunnel either, which is the very thing <c>/split</c> exists to avoid.
        /// </summary>
        private static List<VpnRoute>? SplitFromAddress(string? address)
        {
            if (string.IsNullOrEmpty(address)) return null;
            var at = address.IndexOf("/split", StringComparison.OrdinalIgnoreCase);
            if (at < 0) return null;

            var rest = address[(at + "/split".Length)..].TrimStart('=', ':').Trim('/');
            var routes = new List<VpnRoute>();
            if (rest.Length > 0)
            {
                foreach (var token in rest.Split(new[] { ',', ';', ' ' },
                                                 StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = token.Split('/');
                    var net = parts[0].Trim();
                    // No prefix means a single host.
                    byte prefix = 32;
                    if (parts.Length > 1 && byte.TryParse(parts[1], out var p) && p <= 32)
                        prefix = p;

                    if (System.Net.IPAddress.TryParse(net, out var ip) &&
                        ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        routes.Add(new VpnRoute(new HostName(net), prefix));
                    else
                        Trace($"split route ignored, not an IPv4 network: '{token}'");
                }
            }

            // Nothing usable typed -- or nothing at all after the word -- means the private
            // ranges. Never an empty list, which Connect would read as "no split" and send the
            // whole machine back through the tunnel.
            if (routes.Count == 0)
                foreach (var (network, prefix) in PrivateRanges)
                    routes.Add(new VpnRoute(new HostName(network), prefix));

            return routes;
        }

        /// <summary>
        /// The username and password to log in with.
        ///
        /// Asking as a retry is what makes the platform throw its cached pair away and put
        /// the prompt back up, which is the only way a password mistyped once ever gets
        /// corrected. But the retry form is not always available -- dialled from rasdial with
        /// a pair already on the command line, it comes back E_NOT_SUPPORTED (0x80070032) --
        /// and refusing to connect at all would be far worse than reusing the cache, so the
        /// plain request is the fallback rather than the failure.
        /// </summary>
        private static VpnPickedCredential? FetchCredentials(VpnChannel channel)
        {
            if (System.Threading.Interlocked.Exchange(ref _credentialRejected, 0) != 0)
            {
                Trace("last attempt was rejected, asking for the credential again");
                try
                {
                    return channel.RequestCredentials(VpnCredentialType.UsernamePassword, true, false, null);
                }
                catch (Exception ex)
                {
                    // The HRESULT, because these come back with an empty message: 0x80070032
                    // is the platform saying the retry prompt is not available here.
                    Trace($"retry prompt unavailable (0x{ex.HResult:X8}), using the plain request");
                }
            }

            return channel.RequestCredentials(VpnCredentialType.UsernamePassword, false, false, null);
        }

        /// <summary>
        /// Puts a single code box up and returns what the user typed, or null if they
        /// cancelled or the platform cannot show one. This is the gateway's own second
        /// factor (ret=2). UsernameOtpPin is the credential type whose dialog is a lone code
        /// field; the value lands in AdditionalPin, and PasskeyCredential.Password is the
        /// fallback for platform builds that route a one-time code through the password
        /// field instead.
        /// </summary>
        private static string? RequestCode(VpnChannel channel, string purpose)
        {
            try
            {
                Trace($"requesting code: {purpose}");
                var picked = channel.RequestCredentials(
                    VpnCredentialType.UsernameOtpPin, false, false, null);
                var code = picked?.AdditionalPin;
                if (string.IsNullOrEmpty(code)) code = picked?.PasskeyCredential?.Password;
                return string.IsNullOrEmpty(code) ? null : code;
            }
            catch (Exception ex)
            {
                Trace($"code prompt unavailable (0x{ex.HResult:X8}): {ex.Message}");
                return null;
            }
        }

        public void Connect(VpnChannel channel)
        {
            // Before the profile is read, not after. Reading the configuration is already a
            // call back into the platform, so if that is where a dial stalls -- Settings
            // sitting on "Verifying your sign-in info" until it times out -- a line printed
            // after it never appears and the stall is indistinguishable from Connect never
            // having been called at all.
            // The object number matters more than the entry: whichever object the platform
            // dispatches Connect to is, by definition, one it has associated with the channel.
            // If Disconnect never arrives on that same number, the association is the bug.
            Trace($"FortiPlugin.Connect entered on obj#{_instanceId}");

            // The platform dispatches Connect twice for the same dial -- two activations two
            // milliseconds apart, seen on every reconnect. Both used to run: the loser reached
            // RequestCredentials and came back 0x8007048F, then reported a failed dial on the
            // channel the winner was about to start. Only the first through here does the work.
            if (System.Threading.Interlocked.Exchange(ref _connecting, 1) != 0)
            {
                Trace("a dial is already in progress, leaving this one to it");
                return;
            }

            _tunnelLive = false;
            try
            {
                var target = ResolveServer(channel);
                var (host, port) = (target.Host, target.Port);
                Trace($"FortiPlugin.Connect -> {host}:{port}" +
                      (target.SplitRoutes is null ? "" : $" (split: {target.SplitRoutes.Count} route(s))"));
                channel.LogDiagnosticMessage($"FortiPlugin.Connect -> {host}:{port}");

                // Windows collects and stores the credential; the plugin only ever sees it
                // in memory for the duration of the login POST. The retry flag is what makes
                // the platform ask again instead of handing back the pair it cached on the
                // attempt the gateway just rejected.
                var cred = FetchCredentials(channel);
                if (cred?.PasskeyCredential is null)
                {
                    // Also the shape of a cancelled prompt, which is not an error worth
                    // arming the retry flag for.
                    Trace("no credential returned (prompt cancelled?)");
                    channel.SetErrorMessage("No user name or password was supplied.");
                    return;
                }

                // Rooted for the life of the tunnel. Connect returns as soon as the handshake
                // is done, and a local would be collectible from that moment on -- taking the
                // socket's RCW, and with it the transport the platform is still using, with it.
                //
                // This is also the only place a session is ever disposed apart from Disconnect,
                // deliberately. Closing the socket of a *failed* dial from the failure path
                // instead looked tidier and cost a working tunnel: the socket has already been
                // through AssociateTransport by the time login is refused, and closing it there
                // left the channel holding a dead transport, so the next dial completed the
                // whole handshake, brought the tunnel up, sent packets and received nothing at
                // all. Leaving it to be closed here, at the start of the next dial, keeps the
                // channel's view of the transport consistent -- and the parked read a timed-out
                // handshake leaves behind ends the moment this Dispose closes the socket.
                // Said before the old session is dropped, while its cookie is still to hand.
                // Windows never calls Disconnect on this plugin -- not one FortiPlugin.Disconnect
                // line has ever appeared in a log -- so the gateway is otherwise left believing
                // the session is still live, and holds it for tun-user-ses-timeout. This is the
                // only place there is to say otherwise.
                //
                // Best effort throughout, and hard-bounded: a logout that hangs must not turn a
                // reconnect that would have worked into one that times out. It also only covers
                // a reconnect within the same host process; when Windows tears the process down
                // the cookie goes with it and the thirty seconds have to be waited out.
                var stale = _session;
                if (stale is not null && stale.Cookie.Length > 0)
                {
                    try
                    {
                        FortiSession.LogoutAsync(host, port, stale.Cookie)
                                    .WaitAsync(LogoutTimeout).GetAwaiter().GetResult();
                        Trace("logged the previous session out");
                    }
                    catch (Exception ex)
                    {
                        Trace($"logging the previous session out failed: {ex.Message}");
                    }
                }

                _session?.Dispose();
                _sent = _received = 0;
                _rx.Clear();
                var session = _session = new FortiSession(host, port)
                {
                    // Both sinks: the platform channel needs administrator rights to read,
                    // so the file is the only copy we can actually get at.
                    Log = line => { Trace(line); channel.LogDiagnosticMessage(line); },

                    // Only invoked if the gateway answers login with ret=2; a single-code
                    // dialog goes up and the code comes back for the follow-up POST.
                    TwoFactorPrompt = challenge => RequestCode(channel, $"gateway 2FA: {challenge}"),
                };

                // Before the socket is connected, not after: the platform has to mark the
                // transport as exempt from the tunnel it is about to build, and a socket
                // that is already connected is refused with E_ILLEGAL_STATE_CHANGE.
                channel.AssociateTransport(session.Socket, null);

                // IVpnPlugIn.Connect is synchronous by contract, so the handshake is run to
                // completion here rather than continued on another thread.
                // "Passkey" is the platform's name for the username/password pair; it is not
                // a WebAuthn passkey.
                try
                {
                    session.ConnectAsync(cred.PasskeyCredential.UserName,
                                         cred.PasskeyCredential.Password)
                           .WaitAsync(HandshakeTimeout).GetAwaiter().GetResult();
                }
                catch (TimeoutException)
                {
                    // Named, because silence has a specific and very common cause here: the
                    // gateway is still holding the previous session for the same source
                    // address and will not answer until it lets go. Telling the user to wait
                    // is the difference between a fix and a dead end.
                    throw new TimeoutException(
                        $"gateway {host}:{port} did not answer within {HandshakeTimeout.TotalSeconds:0} " +
                        "seconds. It may still be holding the previous session; wait about " +
                        "30 seconds and try again.");
                }

                // Nothing to clear here any more: FetchCredentials consumed the flag on the
                // way in, so a dial that gets this far has already left it down and the next
                // one is free to use the cache -- which is where a saved sign-in lives.

                var cfg = session.Config;
                _rx.Clear();

                var addresses = new List<HostName> { new HostName(cfg.AssignedIpText) };

                var routes = new VpnRouteAssignment { ExcludeLocalSubnets = true };
                if (target.SplitRoutes is { Count: > 0 } splitRoutes)
                {
                    // A /split on the profile address: only these networks go through the
                    // tunnel, and the machine keeps its own internet for everything else. The
                    // gateway's own route list is deliberately ignored here -- /split is the
                    // user overriding it, and for this gateway it is empty in any case.
                    foreach (var route in splitRoutes)
                        routes.Ipv4InclusionRoutes.Add(route);
                }
                else if (cfg.Routes.Count == 0)
                {
                    // No split-tunnel list means the gateway wants everything.
                    routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("0.0.0.0"), 0));
                }
                else
                {
                    foreach (var (network, prefix) in cfg.Routes)
                        routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName(network), (byte)prefix));
                }

                // DNS has to be assigned here because this gateway rejects both IPCP DNS
                // options; the values come from /remote/fortisslvpn_xml instead.
                var domains = new VpnDomainNameAssignment();
                if (cfg.DnsServers.Count > 0)
                {
                    var servers = cfg.DnsServers.Select(s => new HostName(s)).ToList();
                    // With no suffix from the portal, "." is the only sane scope: internal
                    // names have to resolve, and we cannot guess which ones they are.
                    var scopes = cfg.DnsSuffixes.Count > 0 ? cfg.DnsSuffixes : new List<string> { "." };
                    foreach (var scope in scopes)
                        domains.DomainNameList.Add(new VpnDomainNameInfo(
                            scope, VpnDomainNameType.Suffix, servers, new List<HostName>()));
                }

                Trace($"StartWithMainTransport... mtu={cfg.Mtu}");
                channel.StartWithMainTransport(
                    addresses,
                    null,
                    null,
                    routes,
                    domains,
                    cfg.Mtu,
                    (uint)(cfg.Mtu + FrameOverhead),
                    false,
                    session.Socket);

                // Seeded before the tunnel is declared live, so the first activation after
                // this finds a fresh timestamp and takes the hold. Left at zero it would read
                // as "quiet since year one" and the tunnel would be allowed to sleep before
                // it had carried anything at all.
                System.Threading.Interlocked.Exchange(ref _lastTrafficTicks, DateTime.UtcNow.Ticks);

                _heartbeat?.Dispose();
                // Idle is reported alongside the counters because it is now what decides
                // whether the container may sleep, and a heartbeat that shows frozen counters
                // without it cannot say whether the tunnel is quiet or stuck.
                _heartbeat = new System.Threading.Timer(
                    _ => Trace($"heartbeat: sent={_sent} received={_received} " +
                               $"idle={SinceLastPacket.TotalSeconds:0}s"),
                    null, 10000, 10000);

                // Set last, and only on the path that actually started the channel: it is what
                // tells the next activation to hold the container awake. A heartbeat line every
                // ten seconds is now the proof that it is working -- silence in that log means
                // the container went to sleep under a live tunnel.
                _tunnelLive = true;

                var effectiveRoutes = target.SplitRoutes is { Count: > 0 } sr
                    ? string.Join(" ", sr.Select(r => $"{r.Address.CanonicalName}/{r.PrefixSize}"))
                    : cfg.Routes.Count == 0
                        ? "0.0.0.0/0"
                        : string.Join(" ", cfg.Routes.Select(r => $"{r.Item1}/{r.Item2}"));
                Trace($"tunnel up, IP {cfg.AssignedIpText} mtu={cfg.Mtu} " +
                      $"routes=[{effectiveRoutes}]{(target.SplitRoutes is null ? "" : " split")} " +
                      $"dns=[{string.Join(" ", cfg.DnsServers)}] suffix=[{string.Join(" ", cfg.DnsSuffixes)}]");
                channel.LogDiagnosticMessage($"tunnel up, IP {cfg.AssignedIpText}");
            }
            catch (UnauthorizedAccessException ex)
            {
                // Arms the retry flag for the *next* dial only, so it asks for the password
                // again instead of replaying the one that was just refused. The dial after
                // that goes back to the cache, where a sign-in saved in Settings lives.
                System.Threading.Interlocked.Exchange(ref _credentialRejected, 1);
                Trace($"Connect refused: {ex.Message}");
                channel.SetErrorMessage(ex.Message);
            }
            catch (Exception ex)
            {
                Trace($"Connect failed: {ex}");
                channel.LogDiagnosticMessage($"Connect failed: {ex}");
                channel.SetErrorMessage($"Could not connect: {ex.Message}");
            }
            finally
            {
                System.Threading.Interlocked.Exchange(ref _connecting, 0);
            }
        }

        /// <summary>Non-zero while a dial is being run, so the duplicate Connect is dropped.</summary>
        private static int _connecting;

        public void Disconnect(VpnChannel channel)
        {
            // Timed step by step because a disconnect that feels slow has to be pinned on
            // something before it can be made faster, and there are only two candidates in
            // here: closing the socket, and the platform's own Stop. Everything else is
            // field assignment. If this whole method comes back in single-digit
            // milliseconds -- or is never logged at all -- then the wait is happening
            // outside this plugin and no change in here can shorten it.
            var clock = System.Diagnostics.Stopwatch.StartNew();
            Trace($"FortiPlugin.Disconnect entered (sent={_sent} received={_received})");

            // Before the deferral is released, or the container can be suspended with the
            // teardown half done. Nothing left to keep awake once this returns.
            _tunnelLive = false;
            System.Threading.Interlocked.Exchange(ref _hold, null)?.Finish();

            _heartbeat?.Dispose();
            _heartbeat = null;

            var beforeDispose = clock.ElapsedMilliseconds;
            _session?.Dispose();
            _session = null;
            Trace($"  session closed in {clock.ElapsedMilliseconds - beforeDispose}ms");

            channel.LogDiagnosticMessage("FortiPlugin.Disconnect");
            _rx.Clear();

            var beforeStop = clock.ElapsedMilliseconds;
            channel.Stop();
            Trace($"  channel.Stop in {clock.ElapsedMilliseconds - beforeStop}ms");

            Trace($"FortiPlugin.Disconnect done in {clock.ElapsedMilliseconds}ms");
        }

        public void GetKeepAlivePayload(VpnChannel channel, out VpnPacketBuffer keepAlivePacket)
        {
            // FortiOS holds the tunnel open on LCP echo. Sending our own means an idle
            // session is not dropped for silence.
            keepAlivePacket = null!;
            try
            {
                Trace("keepalive");
                var echo = FortiFrame.Frame(Proto.Lcp, new CtrlPacket(9, 0, new byte[4]).Serialize());
                keepAlivePacket = Wrap(channel.GetVpnSendPacketBuffer(), echo);
            }
            catch (Exception ex)
            {
                channel.LogDiagnosticMessage($"keepalive failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Data-plane counters. Static because the platform activates a fresh plugin object
        /// per background-task event, so an instance field would only ever read zero.
        /// Logged sparsely -- one line per power of two -- so the file stays readable while
        /// still showing whether packets move at all, and in which direction.
        /// </summary>
        private static int _sent, _received;

        /// <summary>How many times the platform has activated this background task.</summary>
        private static int _activations;

        /// <summary>
        /// How many times the class has been constructed, and which construction this object
        /// is. Every other field here is static precisely because the shim log shows the
        /// platform calling CreateInstance again and again -- state had to survive that. But
        /// <see cref="VpnChannel.ProcessEventAsync"/> is handed <c>this</c>, not the state, and
        /// a disconnect event that arrives on a freshly built object the platform never
        /// associated with the channel would be dispatched to nothing at all. That is exactly
        /// what the traces show: the event lands, ProcessEventAsync returns in a millisecond,
        /// Disconnect is never called, and the platform waits out its fifteen second timeout.
        /// Numbering the objects is what turns that from a plausible story into a fact.
        /// </summary>
        private static int _instances;
        private readonly int _instanceId = System.Threading.Interlocked.Increment(ref _instances);

        /// <summary>
        /// The object every event is dispatched on: the first one the platform ever built in
        /// this host process, which is necessarily the one that serviced Connect and therefore
        /// the one the channel belongs to.
        /// </summary>
        private static FortiPlugin? _canonical;

        /// <summary>The live session, kept alive for as long as the tunnel is up.</summary>
        private static FortiSession? _session;

        /// <summary>
        /// Ticks every ten seconds while a tunnel is up and reports the counters. Without it
        /// the log only shows activity when someone happens to generate traffic, which makes
        /// a stalled pump indistinguishable from an idle one.
        /// </summary>
        private static System.Threading.Timer? _heartbeat;

        private static void Count(ref int counter, string direction, int bytes)
        {
            // Stamped on every packet, both directions: this is what tells the hold whether
            // the tunnel is still carrying anything or has gone quiet enough to sleep.
            System.Threading.Interlocked.Exchange(ref _lastTrafficTicks, DateTime.UtcNow.Ticks);

            var n = System.Threading.Interlocked.Increment(ref counter);
            // Every packet at first, so a ping can be matched to the calls it caused, then
            // powers of two once the pattern is established.
            if (n <= 40 || (n & (n - 1)) == 0) Trace($"{direction} {n} ({bytes}B)");
        }

        public void Encapsulate(VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapsulatedPackets)
        {
            // An exception here is swallowed by the platform and shows up only as a tunnel
            // that quietly stops carrying anything, so it is caught and named.
            try
            {
                // Drained, not enumerated. VpnPacketBufferList looks like a collection but
                // does not implement IIterable, so foreach fails the QueryInterface with
                // InvalidCastException and every outbound packet is silently lost.
                while (packets.Size > 0)
                {
                    var packet = packets.RemoveAtBegin();

                    var ip = packet.Buffer.ToArray();
                    var framed = FortiFrame.Frame(Proto.Ipv4, ip);
                    Count(ref _sent, "send", ip.Length);

                    if (_sent <= 2) Trace($"  frame: {Convert.ToHexString(framed, 0, Math.Min(24, framed.Length))}");

                    // Every buffer taken out of the input list has to come back out of
                    // Encapsulate, in one list or the other: the send pool is finite and the
                    // platform only refills it from what is returned here, so leaking one
                    // stalls the whole send path after a dozen packets.
                    if (framed.Length > packet.Buffer.Capacity)
                    {
                        // The platform sizes its send buffers at exactly the tunnel MTU, so a
                        // full-size packet can never hold its own header as well -- lowering
                        // the MTU does not help, the buffers shrink with it. The transport is
                        // a byte stream rather than a datagram channel, so the header goes out
                        // as a buffer of its own directly in front of the untouched packet and
                        // the two meet up again on the wire.
                        if (_sent <= 3) Trace($"  header split off frame of {framed.Length}");
                        encapsulatedPackets.Append(
                            Wrap(channel.GetVpnSendPacketBuffer(), framed[..FrameOverhead]));
                        encapsulatedPackets.Append(packet);
                    }
                    else
                    {
                        encapsulatedPackets.Append(Wrap(packet, framed));
                    }
                }
            }
            catch (Exception ex)
            {
                Trace($"Encapsulate failed: {ex}");
            }
        }

        public void Decapsulate(VpnChannel channel, VpnPacketBuffer encapBuffer,
                                VpnPacketBufferList decapsulatedPackets, VpnPacketBufferList controlPacketsToSend)
        {
            Count(ref _received, "recv", (int)encapBuffer.Buffer.Length);
            _rx.AddRange(encapBuffer.Buffer.ToArray());

            var frames = FortiFrame.Deframe(_rx, out var error);
            if (error is not null)
            {
                Trace($"stream corrupt: {error}");
                channel.LogDiagnosticMessage($"stream corrupt: {error}");
                _rx.Clear();
                return;
            }

            foreach (var (proto, body) in frames)
            {
                if (_received <= 40)
                    Trace($"  <- {Proto.Name(proto)} {body.Length}B" +
                          (proto == Proto.Ipv4 && body.Length >= 20
                              ? $" ip{body[9]} from {body[12]}.{body[13]}.{body[14]}.{body[15]}"
                              : ""));

                if (proto == Proto.Ipv4)
                {
                    decapsulatedPackets.Append(Wrap(channel.GetVpnReceivePacketBuffer(), body));
                    continue;
                }

                // Control traffic never reaches Windows. Echo has to be answered or the
                // gateway tears the session down; everything else is only worth logging.
                var pkt = CtrlPacket.Parse(body);
                if (pkt is null) continue;

                if (proto == Proto.Lcp && pkt.Code == 9)
                {
                    var reply = FortiFrame.Frame(Proto.Lcp, (pkt with { Code = 10 }).Serialize());
                    controlPacketsToSend.Append(Wrap(channel.GetVpnSendPacketBuffer(), reply));
                }
                else
                {
                    Trace($"ignored {Proto.Name(proto)} {pkt.CodeName}");
                    channel.LogDiagnosticMessage($"ignored {Proto.Name(proto)} {pkt.CodeName}");
                }
            }
        }

        /// <summary>
        /// Copies <paramref name="data"/> into a platform-owned buffer and sizes it to fit.
        /// The platform recycles these buffers, so the length must be set every time --
        /// a stale length would send trailing bytes from a previous packet.
        /// </summary>
        private static VpnPacketBuffer Wrap(VpnPacketBuffer target, byte[] data)
        {
            if (data.Length > target.Buffer.Capacity)
                throw new InvalidOperationException(
                    $"packet of {data.Length} bytes exceeds the {target.Buffer.Capacity}-byte buffer");
            // Named explicitly: an unqualified data.CopyTo(target.Buffer, 0) binds to
            // Array.CopyTo instead of the IBuffer extension and does not compile.
            WindowsRuntimeBufferExtensions.CopyTo(data, 0, target.Buffer, 0, data.Length);
            target.Buffer.Length = (uint)data.Length;
            return target;
        }
    }
}

