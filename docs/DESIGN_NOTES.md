# Design Notes

Architecture and scope notes for this NetworkManager VPN plugin implementation of the Check Point SNX/Remote Access protocol. See [Provenance And Licensing](PROVENANCE.md) for independence and licensing details.

## NetworkManager Ownership

- Connections are owned by NetworkManager through `NMVpnServicePlugin`.
- VPN state is published with `Config` and `Ip4Config` instead of a separate controller process.
- DNS is published to NetworkManager; the plugin does not edit `/etc/resolv.conf`.
- Routes are added through netlink and also reported to NetworkManager so the kernel state and NetworkManager state stay aligned.

## Tunnel Support

- The implemented data tunnel is SSL/TCPT.
- IPsec, NAT-T UDP, IPsec UDP TUN, IPsec TCPT TUN, and kernel XFRM integration are not implemented yet.
- The profile still accepts `tunnel-type` and `transport-type` values for configuration compatibility, but activation currently uses the SSL/TCPT tunnel path.

## DNS And Routing

- Gateway-provided DNS servers and DNS suffixes are parsed from SSL `hello_reply`.
- DNS suffixes are emitted as NetworkManager routed domains when `set-routing-domains=true`.
- When a split-DNS gateway provides private DNS servers but omits the matching private route range, the plugin infers a conservative private subnet route for that DNS range. This covers gateways that return hosts like `172.20.0.198` as DNS but do not explicitly return `172.20.0.0/16`.
- Real split DNS still depends on the system NetworkManager DNS backend, such as `systemd-resolved` or `dnsmasq`. Without such a backend, NetworkManager may fall back to a flat `/etc/resolv.conf`, which cannot route different domains to different DNS servers.

## Authentication

- Username/password authentication is implemented through the CCC protocol and NetworkManager secrets.
- MFA challenge continuation is implemented through `secrets_required()` and `NewSecrets()`, reusing the `password` secret as the challenge-code carrier for compatibility with NetworkManager secret agents.
- The auth dialog labels challenge reprompts as `MFA code`.
- Multiple simultaneous MFA factors and SSO/browser Identity Provider flows are not implemented yet.

## User Interfaces

- GNOME Settings is supported through the GTK `NMVpnEditor` plugin (`gnome/`, its own Meson project, requiring gtk4/libnma-gtk4). It links `snx-core` but nothing in `src/` depends back on it. It builds on top of the core backend (`common/`, see below) rather than duplicating it, and KDE doesn't build this at all — the [KDE Plasma/Qt build](INSTALL.md#kde-plasmaqt-editor-build) is an independent tree with no GTK dependency of any kind.
- The classic GTK3 `nm-connection-editor` is not supported yet.
- KDE Plasma is supported through a separate `VpnUiPlugin`/`SettingWidget` (Qt Widgets, not QML — this matches how every VPN editor plasma-nm itself ships is built) in [`plasma/`](../plasma/README.md), with the same field set as the GTK editor: General/Authentication (gateway with login-type "Query...", tunnel/transport type, user/password, optional client certificate) and an Advanced dialog (interface/MTU, DNS, routing, CA certificate, IPsec session), reusing `src/snx-ccc.c` directly for gateway discovery instead of reimplementing it. `plasma-nm` does not load the GTK editor; it has its own plugin discovery (`KPluginFactory`/`KPluginMetaData`, scanning `<Qt plugin dir>/plasma/network/vpn` for a JSON `X-NetworkManager-Services` match), unrelated to the `.name` file's `[GNOME]`/`auth-dialog=` mechanism `nm-snx-auth-dialog.c` uses. `plasma/CMakeLists.txt` builds only the UI plugin (plus a `snx-core` static library for its own tests) — it does not build or install `nm-snx-service`, which lives in the core backend package instead, so the KDE build has no dependency on `gnome/` or GTK4/libnma-gtk4 at all.
- `SnxSettingWidget::setting()` starts from the connection's existing `vpn` data map and only overwrites the keys it (or its Advanced dialog) actually manages, so saving from Plasma does not clobber a value set some other way that this UI happens not to have a field for.
- Unlike GNOME's `libnma-gtk4`, `plasma-nm` does not export a devel package for the API a VPN editor needs (`VpnUiPlugin`, `SettingWidget`, `PasswordField` are private implementation details of the plasma-nm monorepo — runtime `.so` only, no headers, no `pkg-config`/CMake package config). `plasma/vendor/` vendors copies of the three headers needed to compile against that already-installed runtime library; see [Provenance And Licensing](PROVENANCE.md) and [`plasma/README.md`](../plasma/README.md) for what that means for this project's licensing.
- The MFA challenge-code reprompt (the `x-snx-challenge` hint from `secrets_required()`) is handled the same way as the GTK auth dialog: the password prompt's label switches to "MFA code".

## Packaging

- The core NetworkManager service, discover helper, VPN descriptor, and D-Bus policy are built and installed by `common/meson.build` alone. The GTK editor plugin and auth dialog are built and installed separately by `gnome/meson.build`, on top of the core backend.
- Arch packaging is split into three packages with no file overlap: `common/PKGBUILD` (`networkmanager-snx`, the core backend), `gnome/PKGBUILD` (`networkmanager-snx-gnome`, depends on `networkmanager-snx`), and `plasma/PKGBUILD` (`networkmanager-snx-plasma`, depends on `networkmanager-snx`). None of the three restart NetworkManager automatically from package hooks.
