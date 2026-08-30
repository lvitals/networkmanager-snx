# NetworkManager SNX Plugin

C99 NetworkManager VPN plugin for Check Point SNX/Remote Access.

This project is an independent C99 implementation of the Check Point SNX/Remote Access protocol; see [Provenance And Licensing](docs/PROVENANCE.md) for how interoperability was established and what license this code is under. This repository must not contain organization-specific VPN endpoints, usernames, passwords, MFA codes, cookies, certificates, or tokens.

## Scope

This plugin implements a native `NMVpnServicePlugin`: a D-Bus service, a GTK connection editor for GNOME Settings, an authentication dialog, Check Point CCC gateway discovery/authentication, an SSL/TCPT data tunnel, TUN device setup, routing, and DNS publication through NetworkManager `Ip4Config` — no external processes, no `snxctl`/`openconnect`/`strongswan`, no shelling out to `ip`/`route`.

### Supported

- NetworkManager native integration (D-Bus VPN service plugin, no controller process), packaged as the common `networkmanager-snx` backend usable on its own via `nmcli`/`nmtui` (see [Installation](docs/INSTALL.md#core-backend-build))
- GNOME Settings GTK editor and authentication dialog (`gnome/`, optional on top of the backend, see [Installation](docs/INSTALL.md#gnomegtk-editor-build))
- A `plasma-nm` (KDE Plasma) connection editor and secret-agent prompt with the same fields as the GNOME editor (`plasma/`, optional on top of the backend, no GTK dependency, see [Installation](docs/INSTALL.md#kde-plasmaqt-editor-build)) — both editors can be installed at the same time, since neither duplicates the backend
- Check Point CCC gateway discovery and authentication (`src/snx-ccc.c`, raw HTTPS over `gio-2.0`)
- Username/password authentication, with MFA challenge-code continuation through the NetworkManager secret agent
- The SSL/TCPT data tunnel: handshake, SLIM framing, TUN device, and packet forwarding
- IPv4 split routing, gateway-provided DNS, and split DNS through NetworkManager `Ip4Config` (no direct `/etc/resolv.conf` edits)

Validated end-to-end against a production Check Point gateway: authentication, split routes, gateway-provided DNS, routed search domains, and HTTPS access to an internal service through the tunnel.

### Not supported

- IPsec/NAT-T and other non-SSL tunnel transports
- SSO/Identity Provider login
- Multiple simultaneous MFA factors
- The classic GTK3 `nm-connection-editor`
- IPv6

See [Design Notes](docs/DESIGN_NOTES.md) for architecture and scope detail, and [Provenance And Licensing](docs/PROVENANCE.md) for independence and licensing.

## Build

Quick start — build the common backend, then optionally add a desktop editor:

```sh
meson setup common/build common --prefix=/usr --libdir=lib   # core backend, required
meson compile -C common/build
sudo meson install -C common/build

meson setup gnome/build gnome --prefix=/usr --libdir=lib     # GTK/GNOME editor (optional)
meson compile -C gnome/build
sudo meson install -C gnome/build

cmake -S plasma -B plasma/build -DCMAKE_INSTALL_PREFIX=/usr   # KDE Plasma editor (optional)
cmake --build plasma/build
sudo cmake --install plasma/build

sudo busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
sudo systemctl restart NetworkManager
```

The backend alone (`common/`) is enough to make the `snx` VPN type work end to end via `nmcli`/`nmtui`; the GTK and/or Qt editors just add a GUI on top and can both be installed together. The D-Bus reload and NetworkManager restart are what actually register the `snx` VPN type — skip them and NetworkManager will report it has no support for `snx` connections even after a successful build/install. Restarting NetworkManager interrupts active network connections. See [Installation](docs/INSTALL.md) for `DESTDIR` test installs and Arch packaging. Details below.

Runtime/build dependencies:

- C99 compiler
- Meson
- Ninja
- pkg-config
- NetworkManager development headers
- GLib/GIO development headers
- GTK4 development headers (optional; only for the GNOME editor in `gnome/`, see below)
- libnma-gtk4 development headers (optional; same)

Test dependency:

- Valgrind

Build and test the backend, then (optionally) the GTK editor:

```sh
meson setup common/build common --prefix=/usr --libdir=lib
meson compile -C common/build
meson test -C common/build --print-errorlogs
meson compile -C common/build valgrind

meson setup gnome/build gnome --prefix=/usr --libdir=lib
meson compile -C gnome/build
meson test -C gnome/build --print-errorlogs
meson compile -C gnome/build valgrind
```

For an existing build directory, use `--reconfigure`, e.g. `meson setup gnome/build gnome --reconfigure --prefix=/usr --libdir=lib`.

`common/meson.build` builds and installs the core D-Bus service (`nm-snx-service`), the CLI discovery tool (`nm-snx-discover`), the `snx.name` VPN type registration, and the D-Bus policy from `src/` — no GTK dependency, and enough on its own for the `snx` VPN type to work via `nmcli`/`nmtui`. `gnome/meson.build` builds only the GTK `NMVpnEditor` plugin and auth dialog on top of it, requiring gtk4/libnma-gtk4.

The `plasma-nm` (KDE Plasma) editor plugin is a separate Qt/KF/C++ project with its own `CMakeLists.txt` in [`plasma/`](plasma/README.md) — it is not part of the Meson build above, builds only the KDE editor plugin, and has no dependency on `gnome/` or GTK4/libnma-gtk4 at all. See [Installation](docs/INSTALL.md#kde-plasmaqt-editor-build).

## Documentation

- [Installation](docs/INSTALL.md)
- [Configuration](docs/CONFIGURATION.md)
- [Environment Testing](docs/ENVIRONMENT_TESTING.md)
- [Design Notes](docs/DESIGN_NOTES.md)
- [Provenance And Licensing](docs/PROVENANCE.md)
- [plasma-nm Plugin](plasma/README.md)
