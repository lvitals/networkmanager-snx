/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNXAUTH_H
#define SNXAUTH_H

#include "settingwidget.h"

#include <NetworkManagerQt/VpnSetting>

class SnxAuthWidgetPrivate;

/* Secret-agent prompt shown by plasma-nm's PasswordDialog (kded/passworddialog.cpp)
 * when NewSecrets() is needed: covers both the initial password and MFA
 * challenge-code reprompts, mirroring nm-snx-auth-dialog.c's behavior for
 * GNOME. Which case this is comes from the "x-snx-challenge" hint set by
 * nm_vpn_service_plugin_secrets_required() in ../../src/nm-snx-service.c. */
class SnxAuthWidget : public SettingWidget
{
    Q_OBJECT
    Q_DECLARE_PRIVATE(SnxAuthWidget)
public:
    explicit SnxAuthWidget(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent = nullptr);
    ~SnxAuthWidget() override;

    QVariantMap setting() const override;

private:
    SnxAuthWidgetPrivate *const d_ptr;
};

#endif // SNXAUTH_H
