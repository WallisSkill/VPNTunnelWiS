using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking.Vpn;

namespace FortiVpnPlugin
{
    /// <summary>
    /// Registration tool, kept only so the Shell project has an entry point to compile:
    /// the packaged executable is the native FortiVpnHost.exe, which overwrites the
    /// apphost this produces, so nothing ever runs this code.
    ///
    /// install.ps1 creates the profile instead, with
    /// <c>Add-VpnConnection -PlugInApplicationID -CustomConfiguration</c>. That pair does
    /// write the plugin binding (ThirdPartyProfileInfo in rasphone.pbk); it was
    /// -CustomConfiguration missing, not the cmdlet, that made an earlier attempt here
    /// produce a profile RasMan dialled as plain SSTP.
    ///
    /// It is idempotent: run it again to repair or update the profile.
    /// </summary>
    public static class App
    {
        private const string ProfileName = "FortiGate SSL-VPN";

        /// <summary>
        /// Gateway to point the profile at, given on the command line as
        /// <c>https://host:port</c>. Not baked in: the address belongs to whoever installs
        /// this, and a default here would only ever be someone else's network.
        /// </summary>
        private const string ServerUriArgumentHelp =
            "Usage: pass the gateway as the first argument, e.g. https://vpn.example.com:10443";

        private static readonly StringBuilder Journal = new();

        /// <summary>
        /// Everything is mirrored to LocalState\register.log. When Windows launches this
        /// from the Start menu there is no console to read, and a silent failure here is
        /// indistinguishable from the plugin itself being broken.
        /// </summary>
        private static void Say(string line)
        {
            Console.WriteLine(line);
            Journal.AppendLine(line);
        }

        /// <summary>
        /// Server mode has no console and may run for hours, so every line is flushed to
        /// LocalState\server.log as it happens rather than kept for the end.
        /// </summary>
        private static void ServerLog(string line)
        {
            try
            {
                var dir = Windows.Storage.ApplicationData.Current.LocalFolder.Path;
                System.IO.File.AppendAllText(System.IO.Path.Combine(dir, "server.log"),
                    $"{DateTime.Now:HH:mm:ss.fff} {line}{Environment.NewLine}");
            }
            catch
            {
                // A server that cannot log is still a server worth running.
            }
        }

        [MTAThread]
        public static int Main(string[] args)
        {
            var code = 1;
            try
            {
                code = MainAsync(args).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Say($"Unexpected error: {ex}");
            }

            try
            {
                var dir = Windows.Storage.ApplicationData.Current.LocalFolder.Path;
                System.IO.File.WriteAllText(System.IO.Path.Combine(dir, "register.log"), Journal.ToString());
            }
            catch
            {
                // Nothing useful left to do if even LocalState is unwritable.
            }

            return code;
        }

        private static async Task<int> MainAsync(string[] args)
        {
            var remove = args.Any(a => a.Equals("/remove", StringComparison.OrdinalIgnoreCase));
            var agent = new VpnManagementAgent();
            var familyName = Windows.ApplicationModel.Package.Current.Id.FamilyName;

            Say($"Package: {familyName}");
            Say($"APPDATA env  = {Environment.GetEnvironmentVariable("APPDATA")}");
            Say($"ApplicationData = {Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)}");

            // Removing first is what makes a re-run idempotent: AddProfileFromObjectAsync
            // reports Other on a name that already exists rather than replacing it.
            var existing = (await agent.GetProfilesAsync())
                .FirstOrDefault(p => p.ProfileName == ProfileName);
            if (existing is not null)
            {
                var deleted = await agent.DeleteProfileAsync(existing);
                Say($"Removed the previous profile: {deleted}");
            }

            if (remove)
            {
                Say("The connection has been removed from Windows.");
                return 0;
            }

            var serverUri = args.FirstOrDefault(a => !a.StartsWith('/'));
            if (string.IsNullOrWhiteSpace(serverUri))
            {
                Say(ServerUriArgumentHelp);
                return 1;
            }

            var profile = new VpnPlugInProfile
            {
                ProfileName = ProfileName,
                VpnPluginPackageFamilyName = familyName,
                RememberCredentials = true,
                AlwaysOn = false,
            };
            profile.ServerUris.Add(new Uri(serverUri));

            var status = await agent.AddProfileFromObjectAsync(profile);
            Say($"Created the profile: {status}");

            if (status != VpnManagementErrorStatus.Ok)
            {
                Say("Could not create the connection. Check that Developer Mode is on " +
                    "(Settings > System > For developers).");
                return 1;
            }

            Say("");
            Say($"Done. Open Settings > Network & internet > VPN and \"{ProfileName}\" will be there.");
            Say("Click Connect and enter your own SSL-VPN account.");
            return 0;
        }
    }
}
