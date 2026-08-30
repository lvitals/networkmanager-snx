/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx.h"

#include <KPluginFactory>

#include "snxauth.h"
#include "snxwidget.h"

K_PLUGIN_CLASS_WITH_JSON(SnxUiPlugin, "plasmanetworkmanagement_snxui.json")

SnxUiPlugin::SnxUiPlugin(QObject *parent, const QVariantList &)
    : VpnUiPlugin(parent)
{
}

SnxUiPlugin::~SnxUiPlugin() = default;

SettingWidget *
SnxUiPlugin::widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent)
{
    return new SnxSettingWidget(setting, parent);
}

SettingWidget *
SnxUiPlugin::askUser(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent)
{
    return new SnxAuthWidget(setting, hints, parent);
}

QString
SnxUiPlugin::suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const
{
    Q_UNUSED(connection);
    return {};
}

#include "snx.moc"
