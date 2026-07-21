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
            var loud = activation <= 8;
            if (loud) Trace($"IBackgroundTask.Run {taskInstance.TriggerDetails?.GetType().Name}");
            else if (activation % 1000 == 0) Trace($"activation {activation}");

            var activationState = new Activation(taskInstance.GetDeferral());

            // The cancel has to be answered by the activation it belongs to. Completing some
            // other instance's deferral leaves the cancelled one outstanding, and a cancel
            // that goes unanswered does not just end the task -- BrokerInfrastructure event 6,
            // the host process terminated, RAS 829, the live tunnel gone with it.
            taskInstance.Canceled += (_, reason) =>
            {
                Trace($"background task cancelled: {reason}");
                activationState.Finish();
            };

            try
            {
                VpnChannel.ProcessEventAsync(this, taskInstance.TriggerDetails);
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
                if (!_tunnelLive ||
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
                => _rotation = new System.Threading.Timer(
                    _ => { Trace("rotating the hold"); Finish(); },
                    null, RotationInterval, System.Threading.Timeout.InfiniteTimeSpan);

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
        /// How long the whole exchange -- TLS, login, allocation, PPP -- gets before it is
        /// called off. Without a bound, a gateway that completes the TLS handshake and then
        /// says nothing leaves this thread parked in a read for as long as the socket stays
        /// open, and the platform eventually reports a timeout with no reason attached.
        /// FortiOS goes quiet exactly like that once it starts throttling a source that has
        /// failed to log in several times, so the silent case is the one worth naming.
        /// </summary>
        private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(25);

        /// <summary>
        /// Whether the gateway turned the last credential down.
        ///
        /// The platform answers <c>RequestCredentials</c> from its own cache unless the
        /// request is marked as a retry, and it caches whatever was typed even when the dial
        /// then failed. So one mistyped password gets replayed from the cache on every dial
        /// afterwards, the user is never asked again, and the correct password never reaches
        /// the gateway. Marking the next request as a retry is what drops the cached pair and
        /// puts the prompt back.
        ///
        /// Static because the platform builds a fresh plugin object for every event; an
        /// instance field would be forgotten between the failed dial and the next one.
        /// </summary>
        private static bool _credentialRejected;

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
        /// The constants remain only as a fallback for a profile that carries no server.
        /// </summary>
        private static (string Host, string Port) ResolveServer(VpnChannel channel)
        {
            var cfg = channel.Configuration;

            // CustomField first. It is the plugin schema the platform builds from the
            // profile, and the address the user typed into Settings arrives inside it as
            // <serverUrl>. ServerServiceName is not an alternative -- it reads back "0".
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
                        var parsed = ParseServer(custom[(from + open.Length)..to]);
                        if (parsed is not null) return parsed.Value;
                    }
                }
            }
            catch (Exception ex)
            {
                Trace($"CustomField unreadable: {ex.Message}");
            }

            // Each property in its own try: they are read straight off the profile and any
            // one can throw alone. ServerUris is marshalled as System.Uri, so a bare
            // "host:port" with no scheme makes reading the vector throw before any of it
            // can be inspected -- which is why it is not the first thing tried.
            try
            {
                var uri = cfg?.ServerUris?.FirstOrDefault();
                if (uri is not null && !string.IsNullOrEmpty(uri.Host))
                {
                    // Port is -1 when the profile names no port, and FortiOS portals are
                    // https, so 443 is the right default rather than 80.
                    var port = uri.Port > 0 ? uri.Port : 443;
                    return (uri.Host, port.ToString());
                }
            }
            catch (Exception ex)
            {
                Trace($"ServerUris unreadable: {ex.Message}");
            }

            // No built-in gateway to fall back on, deliberately: the address belongs to
            // whoever installs this, not to the plugin. Failing here names the one thing the
            // user can actually fix.
            throw new InvalidOperationException(
                "This connection has no gateway address. Edit it in Settings > Network & " +
                "internet > VPN and enter the address, including the port.");
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

            return (text.Trim('[', ']'), "443");
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
            if (_credentialRejected)
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

        public void Connect(VpnChannel channel)
        {
            // Before the profile is read, not after. Reading the configuration is already a
            // call back into the platform, so if that is where a dial stalls -- Settings
            // sitting on "Verifying your sign-in info" until it times out -- a line printed
            // after it never appears and the stall is indistinguishable from Connect never
            // having been called at all.
            Trace("FortiPlugin.Connect entered");

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
                var (host, port) = ResolveServer(channel);
                Trace($"FortiPlugin.Connect -> {host}:{port}");
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

                // Only now is the pair known good, so the next dial may use the cache again.
                _credentialRejected = false;

                var cfg = session.Config;
                _rx.Clear();

                var addresses = new List<HostName> { new HostName(cfg.AssignedIpText) };

                var routes = new VpnRouteAssignment { ExcludeLocalSubnets = true };
                if (cfg.Routes.Count == 0)
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

                _heartbeat?.Dispose();
                _heartbeat = new System.Threading.Timer(
                    _ => Trace($"heartbeat: sent={_sent} received={_received}"), null, 10000, 10000);

                // Set last, and only on the path that actually started the channel: it is what
                // tells the next activation to hold the container awake. A heartbeat line every
                // ten seconds is now the proof that it is working -- silence in that log means
                // the container went to sleep under a live tunnel.
                _tunnelLive = true;

                Trace($"tunnel up, IP {cfg.AssignedIpText} mtu={cfg.Mtu} " +
                      $"routes=[{string.Join(" ", cfg.Routes.Select(r => $"{r.Item1}/{r.Item2}"))}] " +
                      $"dns=[{string.Join(" ", cfg.DnsServers)}] suffix=[{string.Join(" ", cfg.DnsSuffixes)}]");
                channel.LogDiagnosticMessage($"tunnel up, IP {cfg.AssignedIpText}");
            }
            catch (UnauthorizedAccessException ex)
            {
                // Arms the retry flag, so the next dial asks for the password again instead
                // of replaying the one that was just refused.
                _credentialRejected = true;
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
            Trace($"FortiPlugin.Disconnect (sent={_sent} received={_received})");

            // Before the deferral is released, or the container can be suspended with the
            // teardown half done. Nothing left to keep awake once this returns.
            _tunnelLive = false;
            System.Threading.Interlocked.Exchange(ref _hold, null)?.Finish();

            _heartbeat?.Dispose();
            _heartbeat = null;
            _session?.Dispose();
            _session = null;
            channel.LogDiagnosticMessage("FortiPlugin.Disconnect");
            _rx.Clear();
            channel.Stop();
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

