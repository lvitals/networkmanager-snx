# Installation

These instructions describe the development install for the NetworkManager SNX/Remote Access plugin. The SSL/TCPT tunnel path is implemented; IPsec/NAT-T, SSO/Mobile Access, and a GTK3 editor build remain unfinished.

There are three independent build/install units, all reaching into the common `src/` via relative paths:

- [Core backend build](#core-backend-build) (`common/`, Meson): the D-Bus VPN service (`nm-snx-service`), the CLI discovery tool (`nm-snx-discover`), the `snx.name` VPN type registration, and the D-Bus policy. Required. No GTK or Qt/KF dependency — installing this alone is enough to make the `snx` VPN type work end to end via `nmcli`/`nmtui`.
- [GNOME/GTK editor build](#gnomegtk-editor-build) (`gnome/`, Meson): the GTK `NMVpnEditor` plugin and authentication dialog for GNOME Settings. Optional, on top of the core backend.
- [KDE Plasma/Qt editor build](#kde-plasmaqt-editor-build) (`plasma/`, CMake): the `plasma-nm` connection editor and secret-agent plugin. Optional, on top of the core backend, no GTK dependency.

The two editor builds don't depend on each other and can both be installed at the same time — install whichever desktop(s) you use, or neither if `nmcli`/`nmtui` is enough.

## Core Backend Build

```sh
meson setup common/build common --prefix=/usr --libdir=lib
meson compile -C common/build
meson test -C common/build --print-errorlogs
meson compile -C common/build valgrind
```

If the `common/build` directory already exists with another prefix, reconfigure it:

```sh
meson setup common/build common --reconfigure --prefix=/usr --libdir=lib
```

### Test Install Without Touching The System

Use `DESTDIR` to verify install paths before installing system-wide:

```sh
mkdir -p /tmp/networkmanager-snx-install
DESTDIR=/tmp/networkmanager-snx-install meson install -C common/build
find /tmp/networkmanager-snx-install -type f | sort
```

Expected installed files:

```text
/tmp/networkmanager-snx-install/usr/lib/NetworkManager/VPN/snx.name
/tmp/networkmanager-snx-install/usr/lib/NetworkManager/nm-snx-service
/tmp/networkmanager-snx-install/usr/bin/nm-snx-discover
/tmp/networkmanager-snx-install/usr/share/dbus-1/system.d/nm-snx-service.conf
```

`snx.name` always carries the `[libnm]`/`[GNOME]` sections pointing at the GTK editor plugin/auth dialog paths, even though this build doesn't produce either: harmless if `gnome/` is never installed (GNOME Settings just won't find an SNX editor plugin, though `nmcli`/`nmtui` are unaffected), and means adding the GTK editor later doesn't require reinstalling the backend. KDE Plasma ignores those sections entirely — it discovers VPN UI plugins through their own JSON metadata (see [`plasma/plasmanetworkmanagement_snxui.json`](../plasma/plasmanetworkmanagement_snxui.json)).

### System Install

Install only after the build and tests pass:

```sh
sudo meson install -C common/build
```

Reload D-Bus policy and NetworkManager after installing:

```sh
sudo busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
sudo systemctl restart NetworkManager
```

Restarting NetworkManager interrupts active network connections. At this point the `snx` VPN type is fully functional via `nmcli`/`nmtui` — see [Configuration](CONFIGURATION.md) for the `vpn.data` keys the editors below would otherwise fill in visually, e.g.:

```sh
nmcli connection add type vpn ifname -- vpn-type snx con-name my-snx \
  vpn.data "server=vpn.example.com, username=my.user, login-type=SecurID_password, tunnel-type=ssl"
nmcli connection up my-snx
```

### Uninstall During Development

```sh
sudo ninja -C common/build uninstall
sudo busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig
sudo systemctl restart NetworkManager
```

## GNOME/GTK Editor Build

Requires the [core backend](#core-backend-build) already installed.

```sh
meson setup gnome/build gnome --prefix=/usr --libdir=lib
meson compile -C gnome/build
meson test -C gnome/build --print-errorlogs
meson compile -C gnome/build valgrind
```

`gnome/meson.build` builds only the GTK editor plugin and auth dialog (it recompiles `snx-core` from `../src/` to statically link into both, but does not build or install `nm-snx-service`, `snx.name`, or the D-Bus policy — those are the core backend's job). If the `gnome/build` directory already exists with another prefix, reconfigure it:

```sh
meson setup gnome/build gnome --reconfigure --prefix=/usr --libdir=lib
```

### Test Install Without Touching The System

```sh
mkdir -p /tmp/networkmanager-snx-gnome-install
DESTDIR=/tmp/networkmanager-snx-gnome-install meson install -C gnome/build
find /tmp/networkmanager-snx-gnome-install -type f | sort
```

Expected installed files:

```text
/tmp/networkmanager-snx-gnome-install/usr/lib/NetworkManager/libnm-vpn-plugin-snx.so
/tmp/networkmanager-snx-gnome-install/usr/lib/NetworkManager/nm-snx-auth-dialog
```

No overlap with the core backend's file list above.

### System Install

```sh
sudo meson install -C gnome/build
```

GNOME Settings needs a fresh process to notice a newly installed editor plugin; no D-Bus reload or NetworkManager restart is needed for the plugin itself (only for the backend, above).

### Uninstall During Development

```sh
sudo ninja -C gnome/build uninstall
```

## KDE Plasma/Qt Editor Build

Requires the [core backend](#core-backend-build) already installed. `plasma/CMakeLists.txt` builds only the `plasma-nm` editor/secret-agent plugin — no `nm-snx-service`, `snx.name`, or D-Bus policy here, so it never conflicts with `gnome/`'s install. See [`plasma/README.md`](../plasma/README.md) for scope, dependencies, and licensing notes (it vendors a few LGPL headers from `plasma-nm`, unlike the rest of this MIT project).

```sh
cmake -S plasma -B plasma/build -DCMAKE_INSTALL_PREFIX=/usr
cmake --build plasma/build
ctest --test-dir plasma/build --output-on-failure
cmake --build plasma/build --target valgrind
sudo cmake --install plasma/build
```

Tests reuse the same core test sources as the GNOME/GTK build (`gnome/tests/test-config.c` and friends — `config`, `ip4-config`, `sexpr`, `sexpr-writer`, `obfuscate`, `ccc`, `slim`; the GTK-only `editor-plugin`/`auth-dialog` tests don't apply here, since this build has no GTK editor plugin or auth dialog), compiled here against a `snx-core` static library built from `../src/` — CTest-based rather than Meson's `meson test`, but the same 7 tests. `cmake --build plasma/build --target valgrind` runs them all under Valgrind (`ctest -T memcheck`); it's a no-op if `valgrind` isn't installed.

`plasmanetworkmanagement_snxui.so` installs into Qt's plugin directory (`$(qmake6 -query QT_INSTALL_PLUGINS)/plasma/network/vpn`), where `plasma-nm` discovers VPN UI plugins by scanning for a `X-NetworkManager-Services` match in their JSON metadata (`KPluginMetaData::findPlugins()`). It only changes what Plasma's connection editor and secret-agent dialog can display, not the running VPN service (that's the core backend, already installed and registered). It does need a fresh process to notice it, though: `KPluginMetaData::findPlugins()` is scanned once per process, so System Settings or `plasmashell` instances already running before the install won't show "Check Point SNX/Remote Access" in the Add Connection list until restarted (close/reopen System Settings, or `kquitapp6 plasmashell && kstart plasmashell` for the panel applet).

Uninstall:

```sh
sudo rm "$(qmake6 -query QT_INSTALL_PLUGINS)/plasma/network/vpn/plasmanetworkmanagement_snxui.so"
```

## Arch Package

Three packages, each with its own `PKGBUILD` next to the code it packages, all cloning the full repository as `source`:

- [`common/PKGBUILD`](../common/PKGBUILD) builds `networkmanager-snx` — the core backend, no desktop editor. Required.
- [`gnome/PKGBUILD`](../gnome/PKGBUILD) builds `networkmanager-snx-gnome` — the GNOME GTK editor, depends on `networkmanager-snx`.
- [`plasma/PKGBUILD`](../plasma/PKGBUILD) builds `networkmanager-snx-plasma` — the KDE Plasma editor, no GTK dependency, depends on `networkmanager-snx`.

```sh
cd common && makepkg -si    # core backend, required
cd gnome && makepkg -si     # GNOME editor (optional)
cd plasma && makepkg -si    # KDE Plasma editor (optional)
```

None of the three conflict with each other — `networkmanager-snx-gnome` and `networkmanager-snx-plasma` install only their own editor files and can both be installed at the same time on top of `networkmanager-snx`.

After installing or upgrading `networkmanager-snx`, reload D-Bus policy and restart NetworkManager as shown above; the editor packages need neither step.
