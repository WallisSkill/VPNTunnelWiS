# Status

Working for real. The tunnel comes up, traffic flows both ways, remote desktop into
machines at the office works, and it stays up. No FortiClient, no administrator rights.

## Architecture

Three layers, each one knocking on a door Windows shuts:

    FortiVpnHost.exe   UWP host written in C++ (/SUBSYSTEM:WINDOWS /APPCONTAINER)
      -> FortiVpnShim.dll   WinRT in-process server, starts CoreCLR itself via hostfxr
        -> FortiVpnPlugin.dll   the FortiPlugin class, IVpnPlugIn + IBackgroundTask

- The host must be native: a .NET console host is refused the moment it starts
  (E_APPLICATION_ACTIVATION_EXEC_FAILURE 0x8027025B). The app model requires the image to
  be marked `/APPCONTAINER`, and the activation handshake lives inside
  `CoreApplication::Run`.
- The shim must call hostfxr itself: CsWinRT's `WinRT.Host.dll` returns 0x80008093 for
  every `DllGetActivationFactory` without ever starting the runtime (the platform reports
  it back as 0x80073CFC, which is far harder to read).
- The runtime starts from `dist\` itself rather than from the machine: the layout is a
  self-contained publish, and the shim loads the `hostfxr.dll` sitting next to it. But
  `hostfxr_initialize_for_runtime_config` refuses a self-contained config outright
  (0x80008093, HostApiUnsupportedScenario), because such a config references no framework
  at all, only "included" ones. The way in for that shape is
  `hostfxr_initialize_for_dotnet_command_line` on `FortiVpnHost.dll` -- which runs none of
  the app, only initialises. That is what lets the package need no .NET installed on the
  machine.
- The manifest declares exactly **one** in-process registration. A class may not be
  declared both in-process and out-of-process (deployment returns 0x800700A0), and that is
  precisely why the platform used to wait forever for a registration that never arrived
  (0x8027025A). `ServerName` stays because the `vpnClient` task is refused without it, even
  though no real server stands behind it.

## Four data-plane bugs, all fixed

All four produced the same symptom: the tunnel reports Connected but carries nothing.

1. **`foreach` over a `VpnPacketBufferList`** throws `InvalidCastException` from
   `GetEnumerator()` -- the type does not implement `IIterable`. Every outbound packet was
   lost before it could be framed. It has to be drained with
   `while (list.Size > 0) list.RemoveAtBegin()`.
2. **Send-buffer pool exhaustion.** A buffer taken off the inbound list must be `Append`ed
   back; the old fallback path took one out and returned a different one, leaked steadily,
   and the send path stopped dead after a dozen packets.
3. **The app container gets suspended.** Finishing the last background task means Process
   Lifetime Management suspends the whole process. Measured directly: all 17 host threads
   in `Wait, Suspended`, the CPU idle, not one heartbeat line, and 100% ping loss through
   the tunnel while Windows still said Connected. `Encapsulate` cannot run inside a
   suspended process, so outbound packets are never framed and nothing comes back. There
   must always be an activation holding a deferral -- see "Deferral" below.
4. **Frames overflowing the buffer.** The platform hands out send buffers exactly the size
   of the declared MTU, so a full-size packet can never hold its own 8-byte header; lowering
   the MTU is useless because the buffers shrink with it. The transport is a byte stream and
   not a datagram, so the header goes out as its own short buffer immediately ahead of the
   untouched IP packet, and the two are joined on the wire.

## Notes

- `LogDiagnosticMessage` writes to a channel only an administrator can capture. All
  diagnostics go to `%TEMP%\forti-plugin.log` **inside** the container:
  `%LOCALAPPDATA%\Packages\FortiGateSslVpn.Plugin_ze06k0zwcba52\AC\Temp\`.
  `Trace` needs a lock: two threads writing at once lose both lines to a sharing violation,
  which reads exactly like "Encapsulate was never called".
- `AssociateTransport` must be called **before** the socket connects. An already-connected
  socket is refused with E_ILLEGAL_STATE_CHANGE, surfacing as `InvalidOperationException`.
- The platform builds a new `FortiPlugin` object for **every** event. Any state that has to
  bridge across events must be `static`.
- Fortinet framing: `[0..1]` total length BE = 6+len, `[2..3]` magic 0x5050, `[4..5]` payload
  length, `[6..7]` PPP protocol, then the body. No HDLC, no FCS, no FF 03.
- This gateway returns no `<dns>` and an empty `<split-tunnel-info>`, so `dns=[]` is the
  truth rather than a parse bug: remote in by IP, not by machine name.
- `GetKeepAlivePayload` has never been called.
- `RequestCredentials` returns from **cache** unless the request is marked as a retry, and
  the platform caches even the credential the gateway just refused. One mistyped password
  means every subsequent dial resends that same wrong credential and the user is never
  asked again. The rejection has to be remembered so the next request asks with
  `isRetry: true`. But the retry form is not always available: dialling through `rasdial`
  with credentials supplied throws `0x80070032` (ERROR_NOT_SUPPORTED), so it must fall back
  to the ordinary form rather than fail the whole call.
- **The `_credentialRejected` flag must be *consumed*, not left standing.** "Retry" is an
  instruction for exactly one dial. Leaving it `static` and never lowering it makes it
  outlive the typo that raised it: every later dial in the same process asks with
  `isRetry: true`, and that form **throws the cache away** -- including the username and
  password the user filled in under Settings > Add VPN and had kept by
  `RememberCredentials`. It reads as "this SSL build won't let me save credentials, it
  prompts every single time": it does let you save them, and this is the code discarding
  them. `FetchCredentials` now reads and lowers the flag in a single `Interlocked` step --
  one retry, then back to the cache.
- The handshake has a 25-second deadline. Without one, a gateway that completes the TLS
  handshake and then goes silent (which is how FortiOS blocks a source that has got the
  password wrong a few times) hangs the thread inside a read forever, and the user sees only
  an unexplained "timeout".
- **Every user-visible string** -- `SetErrorMessage`, `Trace`, script output -- is in
  English.
- **Failed dials must not dispose their own session.** The socket has already been through
  `AssociateTransport` by the time a login is refused, and closing it from the failure path
  leaves the channel holding a dead transport: the *next* dial then completes the whole
  handshake, brings the tunnel up, sends packets and receives nothing at all. The session is
  disposed at the start of the following `Connect` instead, which also ends the read a
  timed-out handshake left parked on it.
- **A cancel that is not answered kills the host process, not just the task.** While the
  tunnel's background task held its deferral it got a cancel notification; ignoring it
  produced `BrokerInfrastructure` event 6 ("did not complete in response to a cancel
  notification"), the host was terminated, and RAS reported 829 -- a live session dropping
  roughly ninety seconds in, with no `Disconnect` and no clue in the plugin log.
- **The deferral must rotate: it can neither be held forever nor dropped entirely.** Four
  pieces of evidence, in the order they arrived:
  1. Holding one deferral for the life of the tunnel: *one* activation serves the whole
     tunnel, and it works.
  2. At about 90 seconds the platform cancels it with `ExecutionTimeExceeded`. So one
     deferral cannot cover the life of the tunnel however much one would like it to.
  3. Ignoring that cancel costs the entire host process (the 829 above).
  4. Holding no deferral at all -- the Microsoft sample's shape -- gets the container
     suspended and the tunnel dies with it: measured as all 17 threads `Wait, Suspended`
     and 100% ping loss. Traffic appearing to "keep flowing" in that run was a side effect:
     **outbound** packets wake the container, so only inbound packets that arrive during a
     wake-up get through, and pings come back minutes late. This document previously said
     suspension was harmless; that was wrong, recorded here so it stays wrong on paper too.

  5. Returning the deferral *when it is cancelled* is not enough either.
     `ExecutionTimeExceeded` does not merely end one activation -- it kills the channel's
     data path for the life of the process. Measured: `sent=1874 received=1602` climbing
     steadily, cancel at 11:09:58, and then those two numbers frozen for the next six
     minutes while the heartbeat kept beating. Every redial within that same process got a
     tunnel with `received=0`. And the platform redials after each cancel -- which is
     exactly what "it keeps connecting and disconnecting" looks like from outside.

  So the deferral is **rotated on the plugin's own clock**: whichever activation finds that
  nobody holds it volunteers to, and returns it after 60 seconds -- the measured cancel came
  at 89.7 seconds, so 60 is safe and `ExecutionTimeExceeded` never arrives. Once it is
  returned the platform goes back to activating per packet, and the next packet hands the
  hold to a fresh activation with a fresh 90 seconds. Each deferral may be `Complete`d only
  once (the `Activation` class keeps an `Interlocked` flag), and **only the cancelled
  activation** may return its own deferral -- returning someone else's leaves a cancel that
  nobody answers, which means losing the process.

  6. **And rotating on a clock is still not enough: the hold must not outlive an idle
     tunnel.**
     Measured in a real session: counters frozen at `sent=451999 received=555016` for 50
     minutes, with two `ExecutionTimeExceeded` at 23:13:18 and 23:41:18. The sequence:

         22:58:20  an activation takes the hold, sets a 60-second timer
                   the container is suspended -- the timer freezes with it
         23:13:01  the container wakes (heartbeat resumes), held for ~14.7 minutes
         23:13:18  ExecutionTimeExceeded

     `System.Threading.Timer` **does not run while the container is suspended**, but the
     platform's 90 seconds are **wall-clock**. So any hold that falls across a suspension is
     certain to overrun, and re-reading the clock on wake-up is useless too: by then the
     platform cancelled it long ago.

     The loop sustains itself: the tunnel dies -> no packets -> no activations -> nobody
     takes the hold -> the container sleeps -> the tunnel is deader still.

     So the hold is only taken and kept **while the data path is alive**. After 30 seconds
     of silence it is released, letting the container sleep with **no deferral owed**. The
     trade is latency on the first outbound packet after an idle spell (outbound packets
     wake the container); what it buys is never meeting `ExecutionTimeExceeded` again --
     and that one kills the channel's data path for the life of the process, with no
     recovery. Sleeping can be recovered from; being cancelled costs the process.

     The rotation timer changed from one-shot to **periodic every 5 seconds, re-reading
     wall-clock each time**, because a one-shot measured in process time never comes due
     after a suspension. That `heartbeat` line prints `idle=` alongside -- frozen counters
     alone cannot tell an idle tunnel from a stuck one.
- **The heartbeat is the indicator light.** One line every 10 seconds. Silence in the log
  while the tunnel is supposed to be up means the container has gone to sleep -- the only
  sign of it visible from inside. Alongside it, `rotating the hold` every 60 seconds; seeing
  both plus a rising `received=` means the tunnel is healthy.
- **Windows never calls `Disconnect`.** Not one `FortiPlugin.Disconnect` line appears in any
  log -- Windows kills the host process outright. So the gateway is never told the session
  is over, and it holds it under `tun-user-ses-timeout='30'` with `check-src-ip='1'`: a
  fresh login from the same IP inside those 30 seconds is met with **silence**, hits the
  25-second handshake deadline, and reads as an unexplained "timeout". That is the
  "disconnect then reconnect gives a timeout" symptom. `Connect` now sends
  `GET /remote/logout` with the old cookie **before** discarding the old session, on a
  separate socket (the old socket already belongs to the platform, and writing HTTP into it
  would corrupt the frame stream). 3-second deadline, all errors swallowed. It only rescues
  the case of reconnecting **within the same process**; if the process was killed the cookie
  went with it and the full 30 seconds still has to pass -- so the timeout message says so
  outright.
- **Test dials with junk credentials have a price too.** FortiOS counts those as failed
  logins and blocks the source after a few, and it blocks by completing the TLS handshake
  and then going quiet -- producing exactly the "timeout" above. Verify a build by reading
  the log of a real session, not by dialling test credentials.
- **The platform calls `Connect` twice for a single dial**, two activations a few
  milliseconds apart, on every reconnect. Whichever one loses the race reaches
  `RequestCredentials`, is answered with `0x8007048F`, and reports failure on the very
  channel the winner is about to start. There is now a `_connecting` flag: only the first
  does the work, the second withdraws quietly.
- **Logging must be cheap.** At roughly 2600 activations a minute, opening, writing and
  closing a file under a global lock for every line is unaffordable. `Trace` keeps one
  `StreamWriter` open (`FileShare.ReadWrite`, `AutoFlush`) for the life of the process, and
  `Run` is loud only for the first 8 activations and then one line every 1000.
- **`ProcessEventAsync` returns while the handler is still running.** Measured: it came back
  4 ms after `Connect` was entered, and `Connect` ran for another 150 ms. Anything the
  handler writes at the end of its work is read stale by `Run`'s `finally` -- which is what
  made the deferral handoff above unworkable in the first place.
- The first statement in `Connect` must be a log line, before even reading the profile.
  Reading `channel.Configuration` is itself a call back into the platform, so a hang there
  means the log line printed after it never appears -- and that looks identical to "the
  platform never called Connect".
- **`ProcessEventAsync` must be handed the object that serviced `Connect`, not `this`.**
  The platform uses **a new `FortiPlugin` for every activation** -- numbered, a single
  connect and disconnect runs through `obj#1`, `obj#2`, `obj#3`, `obj#4`. The channel
  belongs to the object that serviced `Connect` (`obj#1`); handing `ProcessEventAsync` a
  stranger means the event arrives but has nowhere to dispatch to.

  The symptom looks nothing like the cause: the user sees **"Disconnecting" for exactly 15
  seconds**, every single time. `Disconnect` is never called, and because nothing ever tells
  the plugin, there is nothing in the log to follow either. Only the ETW provider
  `Microsoft-Windows Networking VPN Plugin Platform`
  (`{E5FC4A0F-7198-492F-9B0F-88FDCBFDED48}`) shows the whole thing:

      00:51:52.403  platform  2002 "Disconnect"
      00:51:52.404  platform  2022 begins
      00:51:52.424  plugin    Run activation 7 -- the event DID arrive
      00:51:52.425  plugin    ProcessEventAsync returned after 1ms, dispatching nothing
      00:52:07.449  platform  2023 -- gives up after 15.045 seconds

  Those 15 seconds are **a platform timeout**, not real work. RAS recorded the disconnect
  after 0.13 seconds; all the rest is the platform sitting waiting for a `Disconnect` that
  never comes. After always passing `obj#1`: `Disconnect` runs in **0 ms** and RAS records
  it **24 ms** later.

  Three hypotheses were chased and all three were wrong, recorded so they are not chased
  again: (1) the plugin holds a deferral the platform cannot reclaim -- cutting the hold
  from 31 seconds to 5.6 moved the stopwatch not at all; (2) the Settings UI just lags
  behind a connection that has already dropped -- `rasdial /disconnect` also took 15.08
  seconds; (3) the trigger details fail to project (`WinRT.IInspectable`) -- the `Connect`
  path that works printed exactly the same type.

  The general lesson: every field in `FortiPlugin` already had to be `static` **precisely
  because** the object is rebuilt constantly. What was missed is that `ProcessEventAsync`
  takes the object and not the state, so `static` could not save it.

## Installing

    powershell -ExecutionPolicy Bypass -File build.ps1      # produces dist\
    powershell -ExecutionPolicy Bypass -File install.ps1    # registers the provider
    powershell -ExecutionPolicy Bypass -File uninstall.ps1
    powershell -ExecutionPolicy Bypass -File package.ps1    # out\FortiVpnPlugin-<ver>.zip
    powershell -ExecutionPolicy Bypass -File installer.ps1  # out\FortiVpnSetup-<ver>.exe

`install.ps1` creates no connection. It only registers the package so that "FortiGate
SSL-VPN" appears in the list of VPN providers; the user adds the connection themselves in
Settings, and the plugin reads the gateway address back out of that profile.

**The address must be typed as `https://host:port`.** This is not a presentational
preference, it is the only form the plugin can read back. Settings accepts a bare
`host:port` without complaint, but both routes that carry an address into the app container
die on it:

- `ServerHostNameList` -- the platform builds each element with `HostName(String)`, and
  `HostName` does not accept a colon. Reading the vector throws `E_INVALIDARG` ("The
  parameter is incorrect. hostName") before yielding a single element. This route is now
  only good for a profile whose address carries no port.
- `ServerUris` -- `System.Uri` reads `118.x.x.x:8080` as scheme `118.x.x.x` and throws
  `Invalid URI: The URI scheme is not valid.`. Adding `https://` makes it parse both host
  and port correctly. It throws at the moment the vector is read, so a bad element cannot
  be filtered out on its own.

`CustomField` (the `<serverUrl>`) is tried ahead of both, but a profile created from
Settings leaves it empty -- it only has a value in a hand-written profile.
`ServerServiceName` is consulted only when the address carries no port, and usually reads
back as "0".

None of this showed up earlier because `ResolveServer` had a hard-coded gateway to fall
back on; removing the constant (to put this on git) is what revealed it had never once
read a real profile.

**Split tunnel rides on the address path.** By default the tunnel carries everything
(`0.0.0.0/0`), because this gateway returns an empty `<split-tunnel-info>` and full tunnel
is the only safe assumption when the gateway says nothing. That takes the whole machine's
internet with it. Appending `/split` to the profile address routes only the RFC1918 private
ranges -- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` -- through the tunnel and leaves
the public internet on the physical adapter: enough to remote-desktop into an office LAN
without losing the machine's own connection. `/split=10.1.0.0/16,192.168.50.0/24` names
exact networks instead (comma-separated, a bare address meaning a single /32).

The path is the only channel that survives. `System.Uri` parses `https://host:port/split`
into host, port and `AbsolutePath`, so the directive arrives clear of the gateway address
that `ResolveServer` needs; a prefix like `split/https://...` would instead make `split` the
URI scheme and fail parsing outright. `SplitFromAddress` reads it from the path in every
branch (`CustomField`, `ServerHostNameList`, `ServerUris`) so the form is the same however
the profile was created. `ExcludeLocalSubnets=true` already keeps the machine's own subnet
off the tunnel, so a home `192.168.x` network keeps working even though `192.168.0.0/16` is
in the tunnel routes. A `/split` token that parses to nothing usable falls back to the
private ranges rather than to a full tunnel -- the whole point was to *stop* sending the
machine through the gateway, so a typo must not quietly do exactly that.

No signed MSIX, no `makeappx`: a signed package can only be installed if the certificate is
in LocalMachine\Root, and putting it there needs an administrator. Registering the layout
directly does not.

`package.ps1` bundles `dist\` + the two scripts + `docs\readme-package.md` into one zip
(~42 MB) that another machine can use as-is, with nothing further to download.

`installer.ps1` produces a single `.exe` (~42 MB) carrying the whole compressed `dist\` as a
resource. It does what `install.ps1` does but needs no PowerShell on the far side. Three
things worth remembering:

- It extracts with the `tar.exe` that has shipped in System32 since Windows 10 1803 -- it
  reads zip, so no decompressor has to be carried along. The package requires 10.0.19041 at
  minimum, so it is certainly present.
- **The `asInvoker` manifest must be embedded.** Windows guesses that a manifest-less `.exe`
  whose name contains "setup" is an installer and demands elevation -- the one thing this
  whole package exists to avoid.
- Link `/MT`. An installer that first requires the VC++ redistributable is meaningless to
  somebody without an administrator.
- It registers via `PackageManager.RegisterPackageAsync` with
  `DeploymentOptions::DevelopmentMode`, the same call `Add-AppxPackage -Register` makes
  underneath.

The one requirement: Developer Mode on.
