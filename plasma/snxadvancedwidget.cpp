/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snxadvancedwidget.h"
#include "nm-snx-service.h"
#include "ui_snxadvanced.h"

#include <QFileDialog>
#include <QPushButton>

#include <KAcceleratorManager>

SnxAdvancedWidget::SnxAdvancedWidget(QWidget *parent)
    : QDialog(parent)
    , m_ui(new Ui::SnxAdvancedWidget)
{
    m_ui->setupUi(this);

    connect(m_ui->caCertBrowse, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("CA Certificate"));
        if (!path.isEmpty())
            m_ui->caCert->setText(path);
    });

    KAcceleratorManager::manage(this);
}

SnxAdvancedWidget::~SnxAdvancedWidget()
{
    delete m_ui;
}

void
SnxAdvancedWidget::loadConfig(const NMStringMap &data)
{
    m_ui->ifName->setText(data.value(QLatin1String(NM_SNX_KEY_IF_NAME)));
    m_ui->mtu->setValue(data.value(QLatin1String(NM_SNX_KEY_MTU)).toInt());

    m_ui->dnsServers->setText(data.value(QLatin1String(NM_SNX_KEY_DNS_SERVERS)));
    m_ui->ignoreDnsServers->setText(data.value(QLatin1String(NM_SNX_KEY_IGNORE_DNS_SERVERS)));
    m_ui->searchDomains->setText(data.value(QLatin1String(NM_SNX_KEY_SEARCH_DOMAINS)));
    m_ui->ignoreSearchDomains->setText(data.value(QLatin1String(NM_SNX_KEY_IGNORE_SEARCH_DOMAINS)));
    m_ui->setRoutingDomains->setChecked(data.value(QLatin1String(NM_SNX_KEY_SET_ROUTING_DOMAINS)) == QLatin1String("true"));
    m_ui->dnsPriority->setValue(data.value(QLatin1String(NM_SNX_KEY_DNS_PRIORITY)).toInt());
    m_ui->disableIpv6->setChecked(data.value(QLatin1String(NM_SNX_KEY_DISABLE_IPV6)) == QLatin1String("true"));

    m_ui->defaultRoute->setChecked(data.value(QLatin1String(NM_SNX_KEY_DEFAULT_ROUTE)) == QLatin1String("true"));
    m_ui->noRouting->setChecked(data.value(QLatin1String(NM_SNX_KEY_NO_ROUTING)) == QLatin1String("true"));
    m_ui->addRoutes->setText(data.value(QLatin1String(NM_SNX_KEY_ADD_ROUTES)));
    m_ui->ignoreRoutes->setText(data.value(QLatin1String(NM_SNX_KEY_IGNORE_ROUTES)));
    m_ui->allowForwarding->setChecked(data.value(QLatin1String(NM_SNX_KEY_ALLOW_FORWARDING)) == QLatin1String("true"));

    m_ui->caCert->setText(data.value(QLatin1String(NM_SNX_KEY_CA_CERT)));
    m_ui->ignoreServerCert->setChecked(data.value(QLatin1String(NM_SNX_KEY_IGNORE_SERVER_CERT)) == QLatin1String("true"));

    m_ui->noKeepalive->setChecked(data.value(QLatin1String(NM_SNX_KEY_NO_KEEPALIVE)) == QLatin1String("true"));
    m_ui->portKnock->setChecked(data.value(QLatin1String(NM_SNX_KEY_PORT_KNOCK)) == QLatin1String("true"));
    m_ui->ikePersist->setChecked(data.value(QLatin1String(NM_SNX_KEY_IKE_PERSIST)) == QLatin1String("true"));
    m_ui->ikeLifetime->setValue(data.value(QLatin1String(NM_SNX_KEY_IKE_LIFETIME)).toInt());
    m_ui->ipLeaseTime->setValue(data.value(QLatin1String(NM_SNX_KEY_IP_LEASE_TIME)).toInt());
}

NMStringMap
SnxAdvancedWidget::setting() const
{
    NMStringMap result;

    result.insert(QLatin1String(NM_SNX_KEY_IF_NAME), m_ui->ifName->text());
    result.insert(QLatin1String(NM_SNX_KEY_MTU), QString::number(m_ui->mtu->value()));

    result.insert(QLatin1String(NM_SNX_KEY_DNS_SERVERS), m_ui->dnsServers->text());
    result.insert(QLatin1String(NM_SNX_KEY_IGNORE_DNS_SERVERS), m_ui->ignoreDnsServers->text());
    result.insert(QLatin1String(NM_SNX_KEY_SEARCH_DOMAINS), m_ui->searchDomains->text());
    result.insert(QLatin1String(NM_SNX_KEY_IGNORE_SEARCH_DOMAINS), m_ui->ignoreSearchDomains->text());
    result.insert(QLatin1String(NM_SNX_KEY_SET_ROUTING_DOMAINS), m_ui->setRoutingDomains->isChecked() ? QStringLiteral("true") : QStringLiteral("false"));
    result.insert(QLatin1String(NM_SNX_KEY_DNS_PRIORITY), QString::number(m_ui->dnsPriority->value()));
    result.insert(QLatin1String(NM_SNX_KEY_DISABLE_IPV6), m_ui->disableIpv6->isChecked() ? QStringLiteral("true") : QStringLiteral("false"));

    result.insert(QLatin1String(NM_SNX_KEY_DEFAULT_ROUTE), m_ui->defaultRoute->isChecked() ? QStringLiteral("true") : QStringLiteral("false"));
    result.insert(QLatin1String(NM_SNX_KEY_NO_ROUTING), m_ui->noRouting->isChecked() ? QStringLiteral("true") : QStringLiteral("false"));
    result.insert(QLatin1String(NM_SNX_KEY_ADD_ROUTES), m_ui->addRoutes->text());
    result.insert(QLatin1String(NM_SNX_KEY_IGNORE_ROUTES), m_ui->ignoreRoutes->text());
    result.insert(QLatin1String(NM_SNX_KEY_ALLOW_FORWARDING), m_ui->allowForwarding->isChecked() ? QStringLiteral("true") : QStringLiteral("false"));

    result.insert(QLatin1String(NM_SNX_KEY_CA_CERT), m_ui->caCert->text());
    result.insert(QLatin1String(NM_SNX_KEY_IGNORE_SERVER_CERT), m_ui->ignoreServerCert->isChecked() ? QStringLiteral("true") : QStringLiteral("false"));

    result.insert(QLatin1String(NM_SNX_KEY_NO_KEEPALIVE), m_ui->noKeepalive->isChecked() ? QStringLiteral("true") : QStringLiteral("false"));
    result.insert(QLatin1String(NM_SNX_KEY_PORT_KNOCK), m_ui->portKnock->isChecked() ? QStringLiteral("true") : QStringLiteral("false"));
    result.insert(QLatin1String(NM_SNX_KEY_IKE_PERSIST), m_ui->ikePersist->isChecked() ? QStringLiteral("true") : QStringLiteral("false"));
    result.insert(QLatin1String(NM_SNX_KEY_IKE_LIFETIME), QString::number(m_ui->ikeLifetime->value()));
    result.insert(QLatin1String(NM_SNX_KEY_IP_LEASE_TIME), QString::number(m_ui->ipLeaseTime->value()));

    return result;
}

#include "moc_snxadvancedwidget.cpp"
