/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snxauth.h"
#include "nm-snx-service.h"
#include "ui_snxauth.h"

class SnxAuthWidgetPrivate
{
public:
    NetworkManager::VpnSetting::Ptr setting;
    Ui_SnxAuthWidget ui;
};

SnxAuthWidget::SnxAuthWidget(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent)
    : SettingWidget(setting, hints, parent)
    , d_ptr(new SnxAuthWidgetPrivate)
{
    Q_D(SnxAuthWidget);
    d->setting = setting;
    d->ui.setupUi(this);

    if (hints.contains(QStringLiteral("x-snx-challenge")))
        d->ui.passwordLabel->setText(QStringLiteral("MFA code:"));

    KAcceleratorManager::manage(this);
}

SnxAuthWidget::~SnxAuthWidget()
{
    delete d_ptr;
}

QVariantMap
SnxAuthWidget::setting() const
{
    Q_D(const SnxAuthWidget);

    NMStringMap secrets;
    QVariantMap secretData;

    if (!d->ui.password->text().isEmpty())
        secrets.insert(QLatin1String(NM_SNX_KEY_PASSWORD), d->ui.password->text());

    secretData.insert(QStringLiteral("secrets"), QVariant::fromValue<NMStringMap>(secrets));
    return secretData;
}

#include "moc_snxauth.cpp"
