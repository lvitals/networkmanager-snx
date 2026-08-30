/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_ERRORS_H
#define SNX_ERRORS_H

#include <glib.h>

typedef enum {
    SNX_ERROR_INVALID_CONFIG,
    SNX_ERROR_INVALID_ADDRESS,
    SNX_ERROR_PARSE,
    SNX_ERROR_NOT_IMPLEMENTED,
} SnxError;

GQuark snx_error_quark(void);

#define SNX_ERROR (snx_error_quark())

#endif
