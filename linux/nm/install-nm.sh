#!/bin/sh
# Puts the FortiGate tunnel into Ubuntu's own network settings, as a NetworkManager VPN type
# backed by this repository's client -- not by openfortivpn.
#
# Run this after install.sh, which is what puts the client on the machine and works out the
# gateway certificate. This script adds the four files NetworkManager needs to know the type
# exists, then writes a connection profile so it shows up in Settings > Network.
#
# What you get afterwards: a VPN entry in Settings, a switch in the top-bar menu, the padlock
# in the panel while connected, and an option to connect automatically at login. What you do
# not get is the type appearing under Settings > "+" -- creating a profile by mouse needs a
# GTK module in C that does not exist yet, so this script writes the profile instead.

set -eu

SERVICE=/usr/libexec/nm-fortivpn-service
DIALOG=/usr/libexec/nm-fortivpn-auth-dialog
NAMEFILE=/usr/lib/NetworkManager/VPN/nm-fortivpn-service.name
DBUSCONF=/usr/share/dbus-1/system.d/nm-fortivpn-service.conf
PROFILE_DIR=/etc/NetworkManager/system-connections
CLIENT=/usr/local/bin/fortivpn
CONF=/etc/fortivpn/gateway.conf
SERVICE_NAME=org.freedesktop.NetworkManager.fortivpn
PROFILE_ID="FortiGate VPN"

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

say()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" = 0 ] || die "run this with sudo."

# ---- uninstall ------------------------------------------------------------------

if [ "${1:-}" = "--uninstall" ]; then
    if have nmcli; then
        nmcli connection delete id "$PROFILE_ID" >/dev/null 2>&1 || true
    fi
    rm -f "$SERVICE" "$DIALOG" "$NAMEFILE" "$DBUSCONF"
    rm -f "$PROFILE_DIR/fortivpn.nmconnection"
    systemctl reload dbus >/dev/null 2>&1 || true
    if have nmcli; then nmcli connection reload >/dev/null 2>&1 || true; fi
    say "Removed. The client itself is untouched; use install.sh --uninstall for that."
    exit 0
fi

# ---- what has to be here already ------------------------------------------------

[ -x "$CLIENT" ] || die "$CLIENT is not installed. Run ./install.sh first."

# The client has to be new enough to be driven by NetworkManager. Without --nm it would
# configure the routing table itself, behind NM's back, and NM could not clean up after it.
if ! "$CLIENT" --help 2>&1 | grep -q -- '--nm'; then
    die "the installed client has no --nm mode. Update it (./install.sh) and run this again."
fi

have nmcli || die "NetworkManager is not installed (no nmcli). This machine has nothing to integrate with."

# dbus-python and pygobject: on an Ubuntu desktop both are already there, pulled in by GNOME
# itself. On a server install they are not, and the service would die on its first import
# with a traceback nobody sees, so check now while there is somebody reading.
if ! python3 -c 'import dbus, dbus.service, dbus.mainloop.glib, gi' >/dev/null 2>&1; then
    say "The VPN service needs python3-dbus and python3-gi."
    printf 'Install them now with apt? [Y/n] '
    read -r answer </dev/tty || answer=n
    case "${answer:-Y}" in
        [Nn]*) die "cannot continue without python3-dbus and python3-gi." ;;
        *) apt-get install -y python3-dbus python3-gi || die "apt could not install them." ;;
    esac
fi

have zenity || warn "zenity is missing: the password prompt falls back to it when the desktop
         does not draw VPN dialogs itself. GNOME does, so this is usually harmless."

# ---- the gateway details --------------------------------------------------------

# install.sh already asked these questions and pinned the certificate. Reuse its answers
# rather than asking again and risking two profiles that disagree.
GATEWAY=""; VPN_USER=""; TRUSTED_CERT=""; FULL_TUNNEL="no"
if [ -r "$CONF" ]; then
    # shellcheck disable=SC1090
    . "$CONF"
    say "Using the gateway from $CONF."
else
    warn "$CONF is missing; asking instead."
fi

while [ -z "$GATEWAY" ]; do
    printf 'Gateway (host:port): '
    read -r GATEWAY </dev/tty || die "no gateway given."
done
while [ -z "$VPN_USER" ]; do
    printf 'Account name: '
    read -r VPN_USER </dev/tty || die "no account name given."
done

case "$FULL_TUNNEL" in [Yy]*|1|true|on) FULL_TUNNEL=yes ;; *) FULL_TUNNEL=no ;; esac

# ---- install the pieces ---------------------------------------------------------

for f in nm-fortivpn-service nm-fortivpn-auth-dialog nm-fortivpn-service.name nm-fortivpn-service.conf; do
    [ -f "$HERE/$f" ] || die "$f is missing from $HERE."
done

install -d /usr/libexec /usr/lib/NetworkManager/VPN /usr/share/dbus-1/system.d "$PROFILE_DIR"
install -m 0755 "$HERE/nm-fortivpn-service"      "$SERVICE"
install -m 0755 "$HERE/nm-fortivpn-auth-dialog"  "$DIALOG"
install -m 0644 "$HERE/nm-fortivpn-service.name" "$NAMEFILE"
install -m 0644 "$HERE/nm-fortivpn-service.conf" "$DBUSCONF"
say "Installed the VPN service, the auth dialog and the D-Bus policy."

# ---- the connection profile -----------------------------------------------------

# Written as a keyfile rather than built with `nmcli connection add`, because nmcli maps
# vpn-type through a table of the types it ships with and a profile it half-understands is
# harder to diagnose than a file that says exactly what it means. `nmcli connection import`
# is no help either: it handles OpenVPN, WireGuard and vpnc, and nothing else.
UUID=$(cat /proc/sys/kernel/random/uuid)
PROFILE="$PROFILE_DIR/fortivpn.nmconnection"

# Do not clobber a profile that already exists -- it may carry autoconnect, a renamed
# connection, or per-user permissions somebody set on purpose.
if [ -f "$PROFILE" ]; then
    say "A profile already exists at $PROFILE; leaving it alone."
else
    umask 077
    cat > "$PROFILE" <<EOF
[connection]
id=$PROFILE_ID
uuid=$UUID
type=vpn
autoconnect=false

[vpn]
service-type=$SERVICE_NAME
gateway=$GATEWAY
user=$VPN_USER
trusted-cert=$TRUSTED_CERT
full-tunnel=$FULL_TUNNEL
two-factor=yes
# 2 is "never saved, ask every time". The one-time code has to be 2 -- a code that could be
# replayed from a keyring is not a second factor. Change password-flags to 1 if you would
# rather GNOME remembered the password in the keyring.
password-flags=2
otp-flags=2

[ipv4]
method=auto

[ipv6]
method=ignore

[proxy]
EOF
    chown root:root "$PROFILE"
    chmod 0600 "$PROFILE"
    say "Wrote the profile to $PROFILE."
fi

# ---- make it live ----------------------------------------------------------------

systemctl reload dbus >/dev/null 2>&1 || true

# NetworkManager reads the VPN type list when it starts. A restart drops nothing on a wired
# or wireless link -- NM re-adopts the connection it already has -- but it does end any VPN
# session that is up right now.
say "Restarting NetworkManager so it picks up the new VPN type ..."
systemctl restart NetworkManager || warn "could not restart NetworkManager; reboot to finish."
sleep 2
nmcli connection reload >/dev/null 2>&1 || true

# ---- did it work -----------------------------------------------------------------

if nmcli -t -f NAME,TYPE connection show 2>/dev/null | grep -q "^$PROFILE_ID:vpn$"; then
    say ""
    say "Done. \"$PROFILE_ID\" is in Settings > Network."
    say "Connect from there, or from the VPN entry in the top-bar menu."
    say ""
    say "To connect automatically at login:"
    say "    nmcli connection modify id '$PROFILE_ID' connection.autoconnect yes"
    say "To watch it while it connects:"
    say "    journalctl -u NetworkManager -f"
else
    warn "the profile is not listed by nmcli. Check: journalctl -u NetworkManager -n 50"
    exit 1
fi
