/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-errors.h"

GQuark
snx_error_quark(void)
{
    return g_quark_from_static_string("snx-error-quark");
}
