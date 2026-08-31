# Provenance And Licensing

This document exists so a distribution or project maintainer can evaluate this repository for redistribution without needing to ask the author. It states, unambiguously: what this project's license is, that the implementation is independent, and where the information needed for protocol interoperability came from.

## License

This project is licensed under the **MIT License**. The full license text is in [`LICENSE`](../LICENSE) at the repository root.

- SPDX identifier: `MIT`.
- Copyright: `Copyright (C) 2026 Leandro Vital <leavitals@gmail.com>`.
- Every file under `src/` and `gnome/` (including `gnome/tests/`) carries an `SPDX-License-Identifier: MIT` header with the same copyright line, so the license of any individual file is unambiguous without needing this document or the repository root.
- `common/meson.build`, `gnome/meson.build`, `packaging/arch/common/PKGBUILD`, `packaging/arch/gnome/PKGBUILD`, and `packaging/arch/plasma/PKGBUILD` all declare `MIT` as project metadata, matching the file-level headers and the `LICENSE` file.

## Independence

This is an independent implementation, written from scratch in C99 against the NetworkManager `libnm` VPN plugin API. It is not a port, fork, or translation of any other project. Concretely:

- No third-party source file, build script, CI configuration, or asset is vendored, embedded, or redistributed anywhere under `src/` or `gnome/` (the C99 core, GTK editor, and D-Bus service this document otherwise describes).
- No third-party code was copied, transliterated, or mechanically translated. Every `.c`/`.h` file in `src/` was written directly against C99, GLib/GIO, and the `libnm` API.
- This project does not link against, depend on, or require any other Check Point VPN client's runtime, libraries, or crates at build or run time.
- The implementation has its own architecture: a native `NMVpnServicePlugin` D-Bus service with no separate controller process, tray icon, or CLI. See [Design Notes](DESIGN_NOTES.md) for the itemized architecture and scope.

**One scoped exception**: `plasma/vendor/` carries verbatim copies of three headers from the KDE `plasma-nm` project (`vpnuiplugin.h`, `settingwidget.h`, `passwordfield.h`; SPDX `LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL`, from https://invent.kde.org/plasma/plasma-nm). This is necessary, not stylistic: unlike GNOME's `libnma-gtk4` (a real, versioned devel library meant for exactly this purpose), `plasma-nm` does not ship a devel package for the API a VPN editor plugin needs — `plasmanm_editor`/`plasmanm_internal` are private implementation libraries of the plasma-nm monorepo, installed as a runtime `.so` only, with no headers, `pkg-config` file, or CMake package config exported for out-of-tree consumers. Every VPN plugin `plasma-nm` itself ships is compiled inside their own tree against their own build for the same reason. These three headers are copied only to declare the ABI the system's already-built `libplasmanm_editor.so` already provides at runtime: nothing from them is reimplemented, this project does not statically link or redistribute `plasma-nm`'s implementation, and the LGPL terms on those three files apply only to those files — they do not relicense `plasma/`'s own code or the rest of this MIT-licensed project. See [`plasma/README.md`](../plasma/README.md) for the full explanation.

## Where the interoperability information came from

Check Point's SNX/CCC wire protocol (the S-expression control format, the CCC HTTPS handshake, the SLIM tunnel framing, and the credential obfuscation scheme) is undocumented and proprietary; Check Point publishes no public specification for it. The protocol facts needed to interoperate with it were established primarily through **direct observation against a real, production Check Point gateway**: capturing and analyzing the actual wire traffic during CCC discovery, authentication, and SSL/TCPT tunnel activation, then cross-checking this implementation's own wire output against that observed traffic for byte-for-byte compatibility. This live validation is the primary source backing every wire-format detail in this codebase, independent of any other reference.

Where general public discussion of this undocumented protocol exists in the open-source community, high-level protocol facts (terminology, message shapes, typical configuration option names) may also have informed this implementation. Only such facts were used — never code. This is the standard clean-room distinction: protocols, wire formats, and interoperability facts are not copyrightable subject matter; a specific implementation's source code is. No third-party source was copied, transliterated, or used as a template for any file implementing the SNX/CCC protocol, the tunnel, or the D-Bus service.

## What this project does not do

- Does not vendor, embed, or redistribute any third-party source, binaries, or build files under `src/` or `gnome/` — see the scoped exception in [Independence](#independence) above for the three KDE headers under `plasma/vendor/`.
- Does not require another Check Point VPN client to be installed, and does not call `snxctl`, `snx`, `openconnect`, `strongswan`, or any other external client as an implementation shortcut.
- Does not copy any other project's process architecture (a separate controller process, CLI, GUI, or tray icon) as a design requirement.

## See also

- [`LICENSE`](../LICENSE) — full MIT text.
- [Design Notes](DESIGN_NOTES.md) — this implementation's own architecture and scope.
