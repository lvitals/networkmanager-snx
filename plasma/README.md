# plasma-nm SNX Plugin

A `plasma-nm` (KDE Plasma NetworkManager applet) VPN editor and secret-agent plugin for the Check Point SNX/Remote Access `NMVpnServicePlugin` implemented in the rest of this repository. It lets Plasma's own connection editor create/edit an SNX VPN profile and prompt for the password (or MFA code) when connecting, instead of falling back to a generic, non-functional entry. Field-for-field, it matches the GTK GNOME editor (`../gnome/nm-snx-editor.c`): same "Query..." gateway login-type discovery, same Advanced Settings tabs, same data keys — the two editors are interchangeable views over the same connection.

This directory is a separate project on purpose: it targets Qt/KF/C++ (see [Build](#build) below for the exact versions), while the GNOME flavor (`../gnome/`) is C99 built with Meson. It has its own `CMakeLists.txt` and builds only the UI plugin, with no dependency on `../gnome/` or GTK4/libnma-gtk4 at all. The core NetworkManager SNX backend (`nm-snx-service`, `snx.name`, the D-Bus policy) lives in the common `networkmanager-snx` package (`../common/`), a runtime dependency of this plugin — see [../docs/INSTALL.md](../docs/INSTALL.md#kde-plasmaqt-editor-build).

## Why C++/CMake instead of C99/Meson

`plasma-nm` VPN editor plugins (`VpnUiPlugin`, `SettingWidget`) are Qt `QObject`-based classes using the meta-object system (`Q_OBJECT`, signals/slots, `moc`), which requires C++. Every VPN plugin plasma-nm ships (OpenVPN, PPTP, VPNC, strongSwan, ...) lives in that same C++/CMake shape inside plasma-nm's own monorepo (`vpn/<name>/`); this directory mirrors that layout so it stays recognizable to anyone familiar with that project.

## Why `vendor/` exists

Unlike GNOME's `libnma-gtk4` (a real, versioned devel library meant for third-party VPN editors), `plasma-nm` does not ship a devel package for the API a VPN plugin needs. `plasmanm_editor`/`plasmanm_internal` are private implementation libraries of the plasma-nm monorepo: the runtime `.so` is installed by the `plasma-nm` package, but no headers, no `pkg-config` file, and no CMake package config are exported for out-of-tree consumers — every plugin plasma-nm ships is compiled inside their own tree, against their own build.

`vendor/` carries copies of the three headers this plugin actually needs (`vpnuiplugin.h`, `settingwidget.h`, `passwordfield.h`; LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL, from https://invent.kde.org/plasma/plasma-nm) purely to declare the ABI that the system's already-built `libplasmanm_editor.so` already provides at runtime — nothing from those headers is reimplemented here, and this plugin does not statically link or redistribute plasma-nm code. `plasmanm_editor_export.h` is the one file in `vendor/` **not** vendored from upstream (it's a build-generated file on their side that's never checked into their source tree); it's our own trivial stand-in, MIT-licensed like the rest of this project. See [../docs/PROVENANCE.md](../docs/PROVENANCE.md) for the full explanation and how this fits the rest of the project's licensing.

The LGPL terms on the three vendored files apply only to those files; they do not relicense this plugin or the rest of `networkmanager-snx`, which stay MIT.

## Scope

General/Authentication (`snxwidget.cpp`, matching `nm-snx-editor.c`'s main widget):

- Gateway address, with a "Query..." button that runs the same CCC gateway login-type discovery as the GTK editor (`../src/snx-ccc.c`, compiled directly into this plugin — read-only, no credentials sent) and populates the login-type dropdown from the gateway's real advertised login methods.
- Login type, tunnel type (`ipsec`/`ssl`), IPsec transport (`auto`/`kernel`/`udp`/`tcpt`).
- User name, password (store-for-user / store-for-all-users / ask-every-time / not-required, same as GTK).
- Optional client certificate: type, path (with a file browser), token ID, and certificate password.

Advanced Settings dialog (`snxadvancedwidget.cpp`, matching `nm-snx-editor.c`'s `build_advanced_dialog()`), same five tabs:

- **General**: interface name, MTU.
- **DNS**: additional/ignored DNS servers, search domains/ignored search domains, split-DNS routing domains, DNS priority, disable IPv6 while connected.
- **Routing**: default route, ignore gateway-provided routes, additional/ignored routes, allow forwarding.
- **Certificate**: CA certificate path (with a file browser), ignore server certificate (insecure).
- **Session**: disable IPsec keepalive, NAT-T port knock, persist IKE session, IKE lifetime, IP lease time.

MFA challenge-code reprompt (`snxauth.cpp`): relabels the password prompt to "MFA code" when the connection's `secrets_required()` hint is `x-snx-challenge`, matching `nm-snx-auth-dialog.c`'s behavior for GNOME.

`SnxSettingWidget::setting()` starts from the connection's existing `vpn` data map (`m_advancedData`, seeded in `loadConfig()`) and only overwrites the keys the main widget or the Advanced dialog actually manage, so a value set some other way (e.g. `nmcli`, a future key this UI doesn't have a field for) survives an edit-and-save from Plasma untouched.

## Build

This produces one installed target:

- `plasmanetworkmanagement_snxui`: the Qt/KF editor plugin. Compiles `../src/snx-ccc.c` and its dependencies (`snx-errors.c`, `snx-obfuscate.c`, `snx-sexpr.c`, `snx-sexpr-writer.c`) directly as C99 sources, to reuse the same gateway login-type discovery code the GTK editor uses instead of reimplementing the CCC HTTPS handshake in Qt.

It also builds (but does not install) a `snx-core` static library from `../src/` for the test suite below. Installing this plugin alone does **not** make NetworkManager support the `snx` VPN type — that requires the `networkmanager-snx` package (`../common/`), which installs `nm-snx-service`, `snx.name`, and the D-Bus policy.

Dependencies (beyond a working `plasma-nm` install, which provides `libplasmanm_editor.so`):

- CMake >= 3.16, a C99 and a C++20 compiler
- Qt6 (Core, Widgets, DBus, Concurrent — the last runs the "Query..." gateway discovery off the UI thread)
- KF6CoreAddons, KF6WidgetsAddons, KF6NetworkManagerQt
- `qmake6` (used at configure time to locate Qt's plugin install directory)
- glib-2.0, gio-2.0, libnm

```sh
cmake -S plasma -B plasma/build -DCMAKE_INSTALL_PREFIX=/usr
cmake --build plasma/build
ctest --test-dir plasma/build --output-on-failure
sudo cmake --install plasma/build
```

Tests reuse the same core test sources `../gnome/meson.build` runs (`../gnome/tests/test-config.c` and friends: `config`, `ip4-config`, `sexpr`, `sexpr-writer`, `obfuscate`, `ccc`, `slim`), compiled here against `snx-core` via CTest instead of `meson test` — same tests, same coverage. `cmake --build plasma/build --target valgrind` runs them all under Valgrind (a no-op if `valgrind` isn't installed).

`plasmanetworkmanagement_snxui.so` installs into Qt's plugin directory (`$(qmake6 -query QT_INSTALL_PLUGINS)/plasma/network/vpn`), where `plasma-nm` discovers VPN UI plugins by scanning for a `X-NetworkManager-Services` match in their JSON metadata (`KPluginMetaData::findPlugins()`).

The UI plugin itself needs no D-Bus policy reload or NetworkManager restart, since it only changes what Plasma's connection editor and secret-agent dialog can display, not the running VPN service (that's `networkmanager-snx`, installed separately — see [../docs/INSTALL.md](../docs/INSTALL.md#core-backend-build) for the reload/restart that registers the `snx` VPN type). It does need a fresh process to notice it, though: Qt/KDE plugin discovery is scanned once per process, not watched for changes. If "Check Point SNX/Remote Access" doesn't show up in the "Add new connection" VPN list, close and reopen System Settings (a fresh process each time), or if you're adding it from the panel's network applet, restart the shell: `kquitapp6 plasmashell && kstart plasmashell`.

## Uninstall

```sh
sudo rm "$(qmake6 -query QT_INSTALL_PLUGINS)/plasma/network/vpn/plasmanetworkmanagement_snxui.so"
```
