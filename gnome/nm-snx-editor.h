/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef NM_SNX_EDITOR_H
#define NM_SNX_EDITOR_H

#include <NetworkManager.h>

#define SNX_TYPE_EDITOR (snx_editor_get_type())

GType snx_editor_get_type(void);

NMVpnEditor *snx_editor_new(NMConnection *connection, GError **error);

#endif
