# Configuration

Do not commit real VPN endpoints, usernames, passwords, MFA codes, cookies, certificates, or tokens to this repository. Keep real connection data in NetworkManager profiles, the desktop secret agent, or local ignored files used only for manual testing.

The examples below use placeholders. Replace them locally with the values from your VPN administrator or private notes.

## Create A Profile With The Graphical Editor

On GNOME, open Settings → Network → VPN → Add VPN and choose "Check Point SNX/Remote Access". This uses `libnm-vpn-plugin-snx.so`, which currently requires a GTK4 host (`gnome-control-center`); the older GTK3 `nm-connection-editor` cannot load it yet (see [Design Notes](DESIGN_NOTES.md)). KDE's `plasma-nm` does not use this editor at all and needs a separate KDE-native plugin.

The editor follows the same layout convention as `networkmanager-openvpn`: the main view only shows "General" (gateway, login type, tunnel type, IPsec transport) and "Authentication" (user name, password, optional client certificate), matching whatever a given profile actually uses instead of listing every option at once. An "Advanced…" button opens a separate window with `Cancel`/`Apply` and its own tabs (General, DNS, Routing, Certificate, Session) for the less commonly changed settings, mirroring OpenVPN's "Advanced Properties" dialog.

## Login Type

`login-type` must be the gateway's internal id for the login method (for example `vpn_Autenticacao_AD`), not the human-readable name shown in a login dropdown (for example "PMC"). These are frequently different strings for the same login method.

In the graphical editor, Login type is a dropdown, not a free-text field. Fill in the gateway address, then click "Query…" right next to it: it fetches the gateway's real login methods (read-only, no credentials sent) and populates the Login type dropdown with them (shown as "Display Name (id)"), auto-selecting the previously configured one if it is still offered. The same lookup is available from the command line; see `docs/ENVIRONMENT_TESTING.md`.

## Split DNS

For VPN domains such as `corp.example.com`, the plugin publishes gateway DNS servers and routed DNS domains to NetworkManager. To keep public names such as `public.example.net` on the normal network DNS while internal names use the VPN DNS, the system must use a NetworkManager split-DNS backend such as `systemd-resolved` or `dnsmasq`.

On systems using `systemd-resolved`, configure this once for the machine:

```sh
sudo systemctl enable --now systemd-resolved
sudo mkdir -p /etc/NetworkManager/conf.d
printf "[main]\ndns=systemd-resolved\n" | sudo tee /etc/NetworkManager/conf.d/10-dns-systemd-resolved.conf
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
sudo systemctl restart NetworkManager
```

This is not per-profile configuration. It applies to all NetworkManager VPN profiles that publish routed DNS domains.

## Create A Profile With nmcli

`nmcli` also works, and is still the safest way to create a development profile without adding private data to the repository.

```sh
nmcli connection add type vpn vpn-type snx con-name "SNX VPN" ifname "*" \
  vpn.user-name "<username>" \
  vpn.data "server-name=<vpn-gateway>,login-type=<login-type>,tunnel-type=ipsec,transport-type=auto,set-routing-domains=true,dns-priority=-100"
```

Optional settings:

```sh
nmcli connection modify "SNX VPN" +vpn.data "if-name=snx-tun"
nmcli connection modify "SNX VPN" +vpn.data "mtu=1300"
nmcli connection modify "SNX VPN" +vpn.data "default-route=false"
nmcli connection modify "SNX VPN" +vpn.data "dns-servers=<dns-ip-1>,<dns-ip-2>"
nmcli connection modify "SNX VPN" +vpn.data "search-domains=<domain-1>,<domain-2>"
nmcli connection modify "SNX VPN" +vpn.data "ca-cert=/path/to/ca.pem"
```

Use `ignore-server-cert=true` only for explicit local testing. It weakens server identity validation and must not be enabled silently.

## Password Handling

Prefer prompting through NetworkManager instead of placing the password on the command line:

```sh
nmcli --ask connection up "SNX VPN"
```

When password storage is implemented, saved secrets should be stored by NetworkManager and the desktop secret agent. Avoid commands that place `vpn.secrets` directly in shell history.

## GNOME

After the editor plugin and authentication dialog are implemented and installed, the connection should be managed through:

- GNOME Settings
- GNOME Shell network menu
- NetworkManager secret agent prompts

## KDE Plasma

After the editor plugin and authentication dialog are implemented and installed, the connection should be managed through:

- KDE Plasma System Settings
- `plasma-nm`
- NetworkManager secret agent prompts

## Current Limitation

The current service uses the SSL/TCPT data tunnel and has been validated against a real gateway through NetworkManager. IPsec/NAT-T and SSO/Mobile Access settings are accepted for configuration compatibility, but those tunnel/authentication paths are not implemented yet.
