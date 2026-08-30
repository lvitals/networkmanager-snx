/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNXWIDGET_H
#define SNXWIDGET_H

#include "settingwidget.h"

#include <NetworkManagerQt/VpnSetting>

namespace Ui
{
class SnxWidget;
}

class SnxAdvancedWidget;

/* plasma-nm connection editor with the same field set as the GTK editor
 * (src/nm-snx-editor.c): General (gateway + login-type discovery, tunnel/
 * transport type), Authentication (user/password, optional client
 * certificate), and an Advanced dialog (interface/MTU, DNS, routing,
 * CA certificate, IPsec session). setting() starts from the connection's
 * existing "vpn" data map and only overwrites the keys this widget or its
 * Advanced dialog manage, so nothing set some other way (e.g. by nmcli)
 * gets clobbered by opening and saving this editor. */
class SnxSettingWidget : public SettingWidget
{
    Q_OBJECT
public:
    explicit SnxSettingWidget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent = nullptr);
    ~SnxSettingWidget() override;

    void loadConfig(const NetworkManager::Setting::Ptr &setting) override;
    void loadSecrets(const NetworkManager::Setting::Ptr &setting) override;

    QVariantMap setting() const override;

    bool isValid() const override;

private Q_SLOTS:
    void onQueryClicked();
    void onUseCertificateToggled(bool checked);
    void onCertPathBrowse();
    void onAdvancedClicked();

private:
    void setCertificateFieldsVisible(bool visible);
    QString selectedLoginType() const;
    void setLoginTypeOptions(const QList<QPair<QString, QString>> &idsAndLabels, const QString &preferredId);

    Ui::SnxWidget *const m_ui;
    NetworkManager::VpnSetting::Ptr m_setting;
    SnxAdvancedWidget *m_advancedDialog;
    NMStringMap m_advancedData;
};

#endif // SNXWIDGET_H
