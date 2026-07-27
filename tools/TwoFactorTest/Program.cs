using FortiVpn;

// Offline test for the FortiGate second-factor login. It compiles src\Plugin\TwoFactor.cs
// and feeds it captured gateway responses -- no socket, no gateway, no credential -- so it
// proves the parsing and the follow-up form without dialling anything.
//
//     dotnet run --project tools\TwoFactorTest
//
// Exit code 0 when every case passes, 1 otherwise, so CI can gate on it.

int failures = 0;

void Check(string name, bool ok, string? detail = null)
{
    Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] {name}");
    if (!ok)
    {
        failures++;
        if (detail is not null) Console.WriteLine($"         {detail}");
    }
}

void Eq(string name, string expected, string actual) =>
    Check(name, expected == actual, $"expected '{expected}', got '{actual}'");

// A FortiGate ret=2 challenge as the gateway actually writes it: a comma-separated ajax
// body. The values here are invented, not captured from any real gateway.
const string Challenge =
    "ret=2,reqid=0139572046,polid=1,grp=Remote_Users,portal=full-access," +
    "magic=0139572046-4 dc7c1f2a9,chal_msg=Please enter your FortiToken code,reqtime=1738000000";

Console.WriteLine("=== challenge detection ===");
Check("ret=2 is a challenge", TwoFactor.IsChallenge(Challenge));
Check("ret=1 is not a challenge", !TwoFactor.IsChallenge("ret=1,redir=/sslvpn/portal.html"));
Check("empty body is not a challenge", !TwoFactor.IsChallenge(""));

Console.WriteLine("\n=== field extraction ===");
Eq("reqid", "0139572046", TwoFactor.Field(Challenge, "reqid"));
Eq("polid", "1", TwoFactor.Field(Challenge, "polid"));
Eq("grp", "Remote_Users", TwoFactor.Field(Challenge, "grp"));
Eq("portal", "full-access", TwoFactor.Field(Challenge, "portal"));
Eq("reqtime", "1738000000", TwoFactor.Field(Challenge, "reqtime"));
Eq("absent field is empty", "", TwoFactor.Field(Challenge, "nosuchfield"));

Console.WriteLine("\n=== the anchor: a short name must not match inside a long one ===");
// "grp" sits inside "grpid". The follow-up POST would carry a wrong group id if Field
// matched the substring, so this is the case the (?:^|,) anchor exists for.
const string GrpIdTrap = "ret=2,grpid=SHOULD_NOT_WIN,grp=CORRECT,magic=abc";
Eq("grp beats grpid", "CORRECT", TwoFactor.Field(GrpIdTrap, "grp"));
Eq("grpid still readable", "SHOULD_NOT_WIN", TwoFactor.Field(GrpIdTrap, "grpid"));

Console.WriteLine("\n=== challenge message ===");
Eq("gateway message used when present",
   "Please enter your FortiToken code", TwoFactor.ChallengeMessage(Challenge));
Eq("default used when absent",
   "Enter your verification code", TwoFactor.ChallengeMessage("ret=2,reqid=1"));

Console.WriteLine("\n=== follow-up form ===");
var form = TwoFactor.BuildOtpForm("alice", "corp-realm", Challenge, "123456");
Console.WriteLine($"  form: {form}");
Check("echoes reqid", form.Contains("reqid=0139572046"));
Check("echoes polid", form.Contains("polid=1"));
Check("echoes grp", form.Contains("grp=Remote_Users"));
Check("echoes portal", form.Contains("portal=full-access"));
Check("echoes reqtime", form.Contains("reqtime=1738000000"));
Check("carries the code", form.Contains("code=123456"));
Check("carries username", form.Contains("username=alice"));
Check("carries realm", form.Contains("realm=corp-realm"));
Check("has empty code2", form.Contains("code2=&"));
Check("marks just_logged_in", form.EndsWith("just_logged_in=1"));

Console.WriteLine("\n=== escaping: a space in magic must be percent-encoded ===");
// magic here holds a space; unescaped it would split the form field. It must arrive as %20.
Check("magic space encoded", form.Contains("magic=0139572046-4%20dc7c1f2a9"));

Console.WriteLine("\n=== escaping: a code with reserved characters ===");
var trickyForm = TwoFactor.BuildOtpForm("bob@corp", "r", "ret=2,reqid=1", "a+b&c=d");
Console.WriteLine($"  form: {trickyForm}");
Check("code ampersand encoded", trickyForm.Contains("code=a%2Bb%26c%3Dd"));
Check("username at-sign encoded", trickyForm.Contains("username=bob%40corp"));

Console.WriteLine();
if (failures == 0)
{
    Console.WriteLine("All 2FA cases passed.");
    return 0;
}
Console.WriteLine($"{failures} case(s) failed.");
return 1;
