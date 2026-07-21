using System.Net;
using System.Net.Security;
using System.Text;
using System.Text.RegularExpressions;

// FortiOS SSL-VPN handshake prober.
//
// Run this yourself -- it asks for your password on the console, keeps it only
// long enough to build the logincheck body, and never writes it anywhere.
// Everything it prints is masked where it matters, so the output is safe to paste back.

// Gateway on the command line: "ProtocolTest vpn.example.com 10443". Nothing about a
// particular network belongs in this file.
if (args.Length < 1)
{
    Console.WriteLine("Usage: ProtocolTest <host> [port]");
    return;
}

var Host = args[0];
var Port = args.Length > 1 ? int.Parse(args[1]) : 443;

var handler = new HttpClientHandler
{
    // A FortiGate presents its own built-in certificate, named after the appliance
    // serial, which no machine trusts by default. Accepting it here is the same thing
    // FortiClient does.
    ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
    AllowAutoRedirect = false,
    UseCookies = true,
    CookieContainer = new CookieContainer(),
};
using var http = new HttpClient(handler) { BaseAddress = new Uri($"https://{Host}:{Port}") };
http.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");

Console.WriteLine($"=== step 1: GET /remote/login ===");
var loginPage = await http.GetStringAsync("/remote/login?lang=en");

string Hidden(string name)
{
    var m = Regex.Match(loginPage, $@"name=""?{name}""?[^>]*value=""([^""]*)""", RegexOptions.IgnoreCase);
    if (!m.Success)
        m = Regex.Match(loginPage, $@"value=""([^""]*)""[^>]*name=""?{name}""?", RegexOptions.IgnoreCase);
    return m.Success ? m.Groups[1].Value : "";
}

var magic = Hidden("magic");
var reqid = Hidden("reqid");
var grpid = Hidden("grpid");
var realm = Hidden("realm");
Console.WriteLine($"  magic='{magic}' reqid='{reqid}' grpid='{grpid}' realm='{realm}'");

Console.Write("\nUsername: ");
var user = Console.ReadLine() ?? "";

Console.Write("Password (khong hien thi): ");
var pw = new StringBuilder();
while (true)
{
    var k = Console.ReadKey(intercept: true);
    if (k.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
    if (k.Key == ConsoleKey.Backspace) { if (pw.Length > 0) pw.Length--; continue; }
    pw.Append(k.KeyChar);
}

Console.WriteLine($"\n=== step 2: POST /remote/logincheck ===");
var form = new List<KeyValuePair<string, string>>
{
    new("ajax", "1"),
    new("username", user),
    new("credential", pw.ToString()),
    new("realm", realm),
    new("magic", magic),
    new("reqid", reqid),
    new("grpid", grpid),
    new("just_logged_in", "1"),
};
pw.Clear();

var resp = await http.PostAsync("/remote/logincheck", new FormUrlEncodedContent(form));
var body = await resp.Content.ReadAsStringAsync();
Console.WriteLine($"  HTTP {(int)resp.StatusCode}");
Console.WriteLine($"  body: {body.Trim()}");

// ret=1 means the credentials were accepted. The cookie may still be missing from the
// container -- on this gateway logincheck actively DELETES SVPNCOOKIE (expiry in 1984)
// and only issues SVPNTMPCOOKIE -- so read the raw Set-Cookie headers at every step.
// Names and attributes are printed, values never are.
string cookieValue = "";

void HarvestCookies(HttpResponseMessage r, string label)
{
    Console.WriteLine($"\n  Set-Cookie tu {label} (chi ten, khong in gia tri):");
    if (!r.Headers.TryGetValues("Set-Cookie", out var scs))
    {
        Console.WriteLine("    (khong co)");
        return;
    }
    foreach (var sc in scs)
    {
        var name = sc.Split('=')[0].Trim();
        var attrs = string.Join(";", sc.Split(';').Skip(1)).Trim();
        // An expiry in the past is a deletion, not a cookie worth keeping.
        var deleted = attrs.Contains("1984") || attrs.Contains("1970");
        Console.WriteLine($"    {name}{(deleted ? "   [XOA]" : "")}   (attrs: {attrs})");

        if (!deleted && name.Equals("SVPNCOOKIE", StringComparison.OrdinalIgnoreCase))
        {
            var val = sc.Split(';')[0].Split('=', 2)[1];
            if (val.Length > 0)
            {
                cookieValue = val;
                handler.CookieContainer.Add(new Cookie("SVPNCOOKIE", val, "/", Host));
            }
        }
    }
}

HarvestCookies(resp, "logincheck");

// Host check turned out to be a formality on this gateway: given the full parameter set
// from redir=, it just bounces to the portal. But it is where the real SVPNCOOKIE is
// issued, so it is not optional either.
// Take everything after "redir=" to end of line: the value is itself a query string full
// of '&', so stopping at the first one strips the parameters the gateway requires.
var redirMatch = Regex.Match(body, @"redir=(\S+)");
if (redirMatch.Success)
{
    var redirUrl = redirMatch.Groups[1].Value.Trim();
    Console.WriteLine("\n=== step 2b: theo redirect sau login ===");
    Console.WriteLine($"  GET {redirUrl}");
    var hc = await http.GetAsync(redirUrl);
    var hcBody = await hc.Content.ReadAsStringAsync();
    Console.WriteLine($"  HTTP {(int)hc.StatusCode} len={hcBody.Length}");
    HarvestCookies(hc, "hostcheck_install");

    var portal = Regex.Match(hcBody, @"document\.location\s*=\s*'([^']+)'");
    if (portal.Success)
    {
        Console.WriteLine($"\n=== step 2c: GET {portal.Groups[1].Value} ===");
        var pr = await http.GetAsync(portal.Groups[1].Value);
        Console.WriteLine($"  HTTP {(int)pr.StatusCode}");
        HarvestCookies(pr, "portal");
    }
}

if (string.IsNullOrEmpty(cookieValue))
{
    var c = handler.CookieContainer.GetCookies(new Uri($"https://{Host}:{Port}"))["SVPNCOOKIE"];
    if (c is { Value.Length: > 0 }) cookieValue = c.Value;
}

if (string.IsNullOrEmpty(cookieValue))
{
    Console.WriteLine("\n  -> Van chua co SVPNCOOKIE that su nao.");
    return;
}
Console.WriteLine($"\n  -> SVPNCOOKIE OK (len={cookieValue.Length}, masked: {cookieValue[..4]}...{cookieValue[^4..]})");

Console.WriteLine($"\n=== step 3: GET /remote/fortisslvpn_xml (tunnel config) ===");
try
{
    var xml = await http.GetStringAsync("/remote/fortisslvpn_xml");
    Console.WriteLine(xml.Length > 3000 ? xml[..3000] + "\n  ...(cat bot)" : xml);
}
catch (Exception ex)
{
    Console.WriteLine($"  loi: {ex.Message}");
}

Console.WriteLine($"\n=== step 4: GET /remote/network (chuyen sang tunnel mode) ===");
Console.WriteLine("  Buoc nay bien ket noi thanh luong PPP. Chi kiem tra header roi dung.");
using var req = new HttpRequestMessage(HttpMethod.Get, "/remote/network");
var netResp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);
Console.WriteLine($"  HTTP {(int)netResp.StatusCode}");
foreach (var h in netResp.Headers)
    Console.WriteLine($"  {h.Key}: {string.Join(", ", h.Value)}");
