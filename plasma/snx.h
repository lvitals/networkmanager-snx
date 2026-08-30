/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef PLASMA_NM_SNX_H
#define PLASMA_NM_SNX_H

#include "vpnuiplugin.h"

#include <QVariant>

class Q_DECL_EXPORT SnxUiPlugin : public VpnUiPlugin
{
    Q_OBJECT
public:
    explicit SnxUiPlugin(QObject *parent = nullptr, const QVariantList & = QVariantList());
    ~SnxUiPlugin() override;

    SettingWidget *widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent) override;
    SettingWidget *askUser(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent) override;

    QString suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const override;
};

#endif // PLASMA_NM_SNX_H
