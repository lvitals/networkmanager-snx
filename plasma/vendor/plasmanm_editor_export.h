/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

/* Not vendored from plasma-nm: this header is generated at plasma-nm's own
 * build time (CMake's generate_export_header(plasmanm_editor)) and is never
 * checked into their source tree, so there is nothing upstream to copy.
 * This is a minimal stand-in for compiling the vendored vpnuiplugin.h /
 * settingwidget.h / passwordfield.h declarations as a *consumer* of the
 * already-built system libplasmanm_editor.so: on ELF/GCC, default symbol
 * visibility already matches what the real macro would expand to for an
 * external consumer, so the export annotations can safely be empty here. */

#ifndef PLASMANM_EDITOR_EXPORT_H
#define PLASMANM_EDITOR_EXPORT_H

#define PLASMANM_EDITOR_EXPORT
#define PLASMANM_EDITOR_NO_EXPORT
#define PLASMANM_EDITOR_DEPRECATED

#endif
