# Environment Testing

These tests validate NetworkManager integration on a real desktop system. They use placeholder data only.

## Install The Current Build

```sh
meson setup common/build common --reconfigure --prefix=/usr --libdir=lib
meson compile -C common/build
meson test -C common/build --print-errorlogs
meson compile -C common/build valgrind
sudo meson install -C common/build

meson setup gnome/build gnome --reconfigure --prefix=/usr --libdir=lib
meson compile -C gnome/build
meson test -C gnome/build --print-errorlogs
meson compile -C gnome/build valgrind
sudo meson install -C gnome/build

sudo busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
sudo systemctl restart NetworkManager
```

Restarting NetworkManager interrupts active network connections.

Verify installed plugin files:

```sh
ls -l /usr/lib/NetworkManager/nm-snx-service
ls -l /usr/lib/NetworkManager/libnm-vpn-plugin-snx.so
ls -l /usr/lib/NetworkManager/nm-snx-auth-dialog
ls -l /usr/lib/NetworkManager/VPN/snx.name
```

## Clear A Stale Development Service

If an older development service remains running after a failed activation test, stop it before retesting:

```sh
pgrep -a nm-snx-service
sudo pkill -x nm-snx-service
```

## Descriptor Recognition Test

Create a temporary placeholder profile:

```sh
nmcli connection add type vpn vpn-type snx con-name "SNX Test Placeholder" ifname "*" \
  vpn.user-name placeholder \
  vpn.data "server-name=vpn.example.com,login-type=vpn_password,tunnel-type=ipsec,transport-type=auto,set-routing-domains=true,dns-priority=-100"
```

Verify that NetworkManager mapped the profile to the SNX service:

```sh
nmcli -f connection.id,connection.type,vpn.service-type,vpn.user-name,vpn.data connection show "SNX Test Placeholder"
```

Expected `vpn.service-type`:

```text
org.freedesktop.NetworkManager.snx
```

Remove the placeholder profile:

```sh
nmcli connection delete "SNX Test Placeholder"
```

## Service Activation Test

Create a temporary placeholder profile:

```sh
nmcli connection add type vpn vpn-type snx con-name "SNX Activation Placeholder" ifname "*" \
  vpn.user-name placeholder \
  vpn.data "server-name=vpn.example.com,login-type=vpn_password,tunnel-type=ipsec,transport-type=auto,set-routing-domains=true,dns-priority=-100"
```

Try to activate it:

```sh
nmcli connection up "SNX Activation Placeholder"
```

Placeholder profiles are expected to fail at DNS, TLS, or authentication because they do not contain a real gateway or credentials. Real profiles with valid credentials should activate through NetworkManager, create the TUN interface, publish IPv4 DNS/routes, and keep normal internet routing unless the profile requests a default VPN route. A timeout that leaves `nm-snx-service` running indicates a service initialization or D-Bus lifecycle bug.

If the profile has no stored password and the command is run without a secret agent, NetworkManager may fail with:

```text
No valid secrets
```

For an interactive secret request, use:

```sh
nmcli --ask connection up "SNX Activation Placeholder"
```

For a real profile, verify the resulting state with:

```sh
ip addr show snx-tun
ip route show
nmcli connection show --active
```

Inspect logs:

```sh
journalctl --no-pager -n 120 -u NetworkManager
pgrep -a nm-snx-service
```

Clean up:

```sh
nmcli connection delete "SNX Activation Placeholder"
sudo pkill -x nm-snx-service
```

## Authentication Dialog Test

`nm-snx-auth-dialog` is the GTK helper that GNOME's secret agent (`nm-applet`, via the `.name` file's `[GNOME] auth-dialog=`) spawns to collect the VPN password; it's part of the optional `gnome/` build (see [Installation](INSTALL.md#gnomegtk-editor-build)). KDE's `plasma-nm` does not use it — it prompts through its own `VpnUiPlugin::askUser()` (`plasma/snxauth.cpp`), independent of this binary. It reads the connection's data and known secrets on stdin and prints a `[VPN Plugin UI]`-format key file describing which secrets still need to be asked.

Exercise it directly without a desktop secret agent:

```sh
printf 'DATA_KEY=server-name\nDATA_VAL=vpn.example.com\nDATA_KEY=login-type\nDATA_VAL=vpn_password\nDONE\n' | \
  /usr/lib/NetworkManager/nm-snx-auth-dialog \
    -n "SNX Test Placeholder" -u "$(uuidgen)" -s org.freedesktop.NetworkManager.snx --external-ui-mode
```

Expected output includes a `[password]` group with `ShouldAsk=true` because no password was supplied on stdin. Add `SECRET_KEY=password` / `SECRET_VAL=<placeholder>` lines before `DONE` to see `ShouldAsk=false` instead.

Drop `--external-ui-mode` (and add `-i`/`--allow-interaction`) from a graphical session to see the real GTK password prompt:

```sh
printf 'DATA_KEY=server-name\nDATA_VAL=vpn.example.com\nDATA_KEY=login-type\nDATA_VAL=vpn_password\nDONE\n' | \
  /usr/lib/NetworkManager/nm-snx-auth-dialog \
    -n "SNX Test Placeholder" -u "$(uuidgen)" -s org.freedesktop.NetworkManager.snx -i
```

The full desktop-integrated path is exercised by `nmcli --ask connection up` or activating the profile from GNOME's secret agent, which invokes this binary automatically because it is referenced from `snx.name`. Activating from `plasma-nm` (KDE) does not go through this binary; it prompts through `plasma`'s own `askUser()` widget instead.

## Gateway Discovery Test

`nm-snx-discover` sends a single read-only CCC `ClientHello` request (no credentials, no session) and prints the gateway's real login-type ids. Use it to find the correct `login-type` value before creating a profile — the id (e.g. `vpn_Autenticacao_AD`) is usually different from the name shown in a login dropdown (e.g. "PMC"):

```sh
./common/build/nm-snx-discover vpn.example.com
```

Add `--insecure` only for gateways with a self-signed or otherwise untrusted certificate, understanding that this disables certificate validation for that request.
