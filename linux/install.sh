#!/bin/sh
# One command, and afterwards the VPN is an icon in the app grid.
#
#     sudo ./install.sh                    ask for the gateway and account, then install
#     sudo ./install.sh --gateway host:port --user alice
#     sudo ./install.sh --uninstall        remove everything this put on the machine
#
# What it does that the person installing would otherwise have to do by hand: pick the
# right binary for the CPU, fetch it, read the gateway certificate's fingerprint and pin
# it, write the config, and register the polkit action and desktop entry that make the
# tunnel dialable without a terminal or sudo.
#
# It never asks for the VPN password. That is entered at connect time, in the desktop
# prompt, and nothing here or in the config file ever holds it.

set -eu

REPO=WallisSkill/VPNTunnelWiS
BIN=/usr/local/bin/fortivpn
GUI=/usr/local/bin/fortivpn-gui
SESSION=/usr/libexec/fortivpn-session
POLICY=/usr/share/polkit-1/actions/org.fortivpn.session.policy
DESKTOP=/usr/share/applications/fortivpn.desktop
CONFDIR=/etc/fortivpn
CONF=$CONFDIR/gateway.conf

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

say()  { printf '%s\n' "$*"; }
step() { printf '  %s\n' "$*"; }
die()  { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Help before the root check: making someone type sudo to find out what a script does is
# backwards, and the answer is the comment block at the top of this file.
case "${1:-}" in
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac

[ "$(id -u)" = "0" ] || die "run this with sudo: sudo ./install.sh"

# ---- uninstall -----------------------------------------------------------------

if [ "${1:-}" = "--uninstall" ] || [ "${1:-}" = "-u" ]; then
    say "Removing the FortiGate VPN integration ..."
    # Before deleting the helper, since it is what knows how to tear the routes down.
    [ -x "$SESSION" ] && "$SESSION" down >/dev/null 2>&1 || true
    # Each test is its own if: "[ -e f ] && rm" is a failing command when the file is
    # already gone, and set -e would abandon the uninstall halfway through.
    for f in "$DESKTOP" "$POLICY" "$SESSION" "$GUI" "$BIN"; do
        if [ -e "$f" ]; then rm -f "$f"; step "removed $f"; fi
    done
    # The config is deliberately kept: it holds the gateway and the pinned fingerprint,
    # which are a nuisance to reconstruct and contain no secret.
    if [ -f "$CONF" ]; then
        say "Kept $CONF (gateway settings, no password). Delete it to finish clean."
    fi
    have update-desktop-database && update-desktop-database /usr/share/applications 2>/dev/null || true
    say "Done."
    exit 0
fi

# ---- arguments -----------------------------------------------------------------

GATEWAY=; VPN_USER=; FULL_TUNNEL=no
while [ $# -gt 0 ]; do
    case "$1" in
        --gateway) GATEWAY=${2:?--gateway needs a value}; shift 2 ;;
        --user)    VPN_USER=${2:?--user needs a value};   shift 2 ;;
        --full)    FULL_TUNNEL=yes; shift ;;
        -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)         die "unknown option: $1" ;;
    esac
done

# ---- the binary ----------------------------------------------------------------

case "$(uname -m)" in
    x86_64|amd64)  RID=linux-x64 ;;
    aarch64|arm64) RID=linux-arm64 ;;
    *) die "unsupported architecture: $(uname -m) (builds exist for x86_64 and aarch64)" ;;
esac

say "Installing the FortiGate VPN client ($RID) ..."

# Prefer a binary sitting next to this script: that is the offline case, and someone who
# already downloaded it should not have it fetched again behind their back.
LOCAL=
for candidate in "$HERE/fortivpn-$RID" "$HERE/fortivpn" "$HERE/../fortivpn-$RID"; do
    if [ -f "$candidate" ]; then LOCAL=$candidate; break; fi
done

if [ -n "$LOCAL" ]; then
    install -m 755 "$LOCAL" "$BIN"
    step "installed $BIN from $LOCAL"
else
    URL="https://github.com/$REPO/releases/latest/download/fortivpn-$RID"
    step "downloading $URL"
    TMP=$(mktemp)
    if have curl;   then curl -fsSL "$URL" -o "$TMP" || die "download failed"
    elif have wget; then wget -qO "$TMP" "$URL"      || die "download failed"
    else die "neither curl nor wget is installed, and no fortivpn-$RID was found next to this script"
    fi
    # A 404 from the release page arrives as a small HTML body, not as an error, and would
    # otherwise be installed as though it were the client.
    [ "$(wc -c < "$TMP")" -gt 1000000 ] || die "the download is not a client binary -- check that the release has fortivpn-$RID"
    install -m 755 "$TMP" "$BIN"; rm -f "$TMP"
    step "installed $BIN"
fi

# ---- gateway and account -------------------------------------------------------

# Read from the terminal directly, so prompting still works when this script is piped in.
prompt() {
    _label=$1; _default=${2:-}; _answer=
    if [ -r /dev/tty ]; then
        printf '%s%s: ' "$_label" "${_default:+ [$_default]}" > /dev/tty
        IFS= read -r _answer < /dev/tty || _answer=
    fi
    printf '%s' "${_answer:-$_default}"
}

# Carry forward whatever a previous install worked out, so re-running is not an interrogation.
# The config assigns the same variable names the options above set, so the command line has
# to be parked across the sourcing and put back -- otherwise --gateway would be silently
# overwritten by the old value and the install would quietly not do what was asked.
ARG_GATEWAY=$GATEWAY; ARG_USER=$VPN_USER; ARG_FULL=$FULL_TUNNEL
OLD_GATEWAY=; OLD_USER=
if [ -r "$CONF" ]; then
    # shellcheck disable=SC1090
    . "$CONF" 2>/dev/null || true
    OLD_GATEWAY=${GATEWAY:-}; OLD_USER=${VPN_USER:-}
fi
GATEWAY=$ARG_GATEWAY; VPN_USER=$ARG_USER; FULL_TUNNEL=$ARG_FULL

[ -n "$GATEWAY" ]  || GATEWAY=$(prompt "Gateway (host:port)" "$OLD_GATEWAY")
[ -n "$GATEWAY" ]  || die "a gateway is required"
[ -n "$VPN_USER" ] || VPN_USER=$(prompt "Account name" "$OLD_USER")

# Split for the certificate probe. Any scheme or trailing path the user pasted is dropped;
# the client parses the same way, so what is stored stays exactly what they typed.
PROBE=${GATEWAY#*://}
PROBE=${PROBE%%/*}
case "$PROBE" in
    *:*) HOST=${PROBE%:*}; PORT=${PROBE##*:} ;;
    *)   HOST=$PROBE;      PORT=443 ;;
esac

# ---- pin the certificate -------------------------------------------------------

TRUSTED_CERT=
if have openssl; then
    step "reading the gateway certificate from $HOST:$PORT"
    # SNI only for a real hostname: sending an IP literal as a servername is invalid and
    # some stacks drop the handshake over it.
    SNI=
    case "$HOST" in
        *[!0-9.]*) SNI="-servername $HOST" ;;
    esac
    # shellcheck disable=SC2086
    TRUSTED_CERT=$(openssl s_client -connect "$HOST:$PORT" $SNI </dev/null 2>/dev/null |
                   openssl x509 -noout -fingerprint -sha256 2>/dev/null |
                   sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z') || TRUSTED_CERT=
fi

if [ -n "$TRUSTED_CERT" ]; then
    step "pinned $TRUSTED_CERT"
else
    say ""
    say "  WARNING: could not read the gateway certificate."
    say "  The client will accept whatever certificate is presented and print its"
    say "  fingerprint on first connect. Put that value in TRUSTED_CERT in $CONF"
    say "  so nothing else is ever accepted."
    say ""
fi

# ---- write the pieces ----------------------------------------------------------

mkdir -p "$CONFDIR"
cat > "$CONF" <<EOF
# FortiGate SSL-VPN, read by /usr/libexec/fortivpn-session. Root-owned on purpose: it is
# what stops an unprivileged caller from pointing the privileged helper somewhere else.
#
# No password lives here. It is typed into the desktop prompt at connect time.

GATEWAY=$GATEWAY
VPN_USER=$VPN_USER

# SHA-256 of the gateway certificate. Empty means "accept anything", which is worth fixing:
# the client prints the real fingerprint on connect.
TRUSTED_CERT=$TRUSTED_CERT

# yes routes everything through the tunnel even when the portal pushes split routes.
FULL_TUNNEL=$FULL_TUNNEL
EOF
chmod 644 "$CONF"
step "wrote $CONF"

mkdir -p "$(dirname "$SESSION")"
install -m 755 "$HERE/fortivpn-session"            "$SESSION"
install -m 755 "$HERE/fortivpn-gui"                "$GUI"
install -m 644 "$HERE/org.fortivpn.session.policy" "$POLICY"
install -m 644 "$HERE/fortivpn.desktop"            "$DESKTOP"
step "installed the helper, the launcher, the polkit action and the desktop entry"

have update-desktop-database && update-desktop-database /usr/share/applications 2>/dev/null || true

have zenity || {
    say ""
    say "  NOTE: zenity is not installed, and the desktop prompts need it:"
    say "        sudo apt install zenity"
}

say ""
say "Done. \"FortiGate VPN\" is now in your applications."
say "Click it to connect; click it again to disconnect. No terminal, no sudo."
say ""
say "Gateway  $GATEWAY"
say "Account  ${VPN_USER:-<asked at connect time>}"
say "Remove   sudo ./install.sh --uninstall"
