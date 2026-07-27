using System;
using System.Text.RegularExpressions;

namespace FortiVpn;

/// <summary>
/// The parsing and form-building behind a FortiGate second-factor login, kept apart from
/// FortiSession on purpose: there is no socket and no WinRT here, only strings in and a
/// string out, so it can be exercised against a captured gateway response without dialling
/// anything. tools\TwoFactorTest compiles this very file and asserts against it.
///
/// The exchange it serves: a login POST is answered with <c>ret=2</c> when the account has
/// a second factor. The body is a comma-separated list carrying the fields the follow-up
/// POST must echo back verbatim -- reqid, polid, grp, portal, magic, reqtime -- next to the
/// code the user types. This mirrors what FortiClient and openfortivpn send.
/// </summary>
internal static class TwoFactor
{
    /// <summary>True when the login response is a second-factor challenge rather than a
    /// straight accept (ret=1) or reject.</summary>
    internal static bool IsChallenge(string body) =>
        body is not null && body.Contains("ret=2");

    /// <summary>
    /// One field out of the comma-separated challenge body. Anchored on start-or-comma so
    /// that a shorter name cannot be caught inside a longer one -- "grp" does not match the
    /// "grp" inside "grpid", because what follows the name here must be "=". Returns "" when
    /// the field is absent.
    /// </summary>
    internal static string Field(string body, string name)
    {
        if (string.IsNullOrEmpty(body)) return "";
        var m = Regex.Match(body, $@"(?:^|,)\s*{Regex.Escape(name)}=([^,\r\n]*)",
                            RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value.Trim() : "";
    }

    /// <summary>
    /// The human-readable prompt to show. The gateway's own <c>chal_msg</c> when it sent
    /// one -- "Please enter your token code" and the like -- and a plain default when it did
    /// not, so the box is never blank.
    /// </summary>
    internal static string ChallengeMessage(string body)
    {
        var msg = Field(body, "chal_msg");
        return msg.Length > 0 ? msg : "Enter your verification code";
    }

    /// <summary>
    /// The body of the follow-up POST to /remote/logincheck: every field the challenge named,
    /// echoed back untouched, plus the code. realm comes from the login page rather than the
    /// challenge body, so it is passed in. Both the code and the username are URL-escaped
    /// because either can hold characters that would otherwise break the form.
    /// </summary>
    internal static string BuildOtpForm(string username, string realm, string body, string code)
    {
        string F(string n) => Uri.EscapeDataString(Field(body, n));
        return $"username={Uri.EscapeDataString(username)}" +
               $"&realm={Uri.EscapeDataString(realm)}" +
               $"&reqid={F("reqid")}" +
               $"&polid={F("polid")}" +
               $"&grp={F("grp")}" +
               $"&portal={F("portal")}" +
               $"&magic={F("magic")}" +
               $"&reqtime={F("reqtime")}" +
               $"&code={Uri.EscapeDataString(code)}" +
               $"&code2=&just_logged_in=1";
    }
}
