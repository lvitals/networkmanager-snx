/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snxwidget.h"
#include "nm-snx-service.h"
#include "snxadvancedwidget.h"
#include "ui_snx.h"

#include <QFileDialog>
#include <QFutureWatcher>
#include <QMessageBox>
#include <QtConcurrentRun>

extern "C" {
#include "snx-ccc.h"
}

namespace
{

struct SnxQueryResult {
    bool ok = false;
    QString errorMessage;
    QList<QPair<QString, QString>> options; // (id, display name)
};

SnxQueryResult
snxRunQuery(QString server, bool ignoreServerCert)
{
    SnxQueryResult result;
    QByteArray serverUtf8 = server.toUtf8();
    SnxCccOptions options = {};
    SnxGatewayInfo *info = nullptr;
    GError *error = nullptr;

    options.server_name = serverUtf8.data();
    options.ignore_server_cert = ignoreServerCert;

    if (!snx_ccc_get_gateway_info(&options, &info, &error)) {
        result.errorMessage = error != nullptr ? QString::fromUtf8(error->message) : QStringLiteral("Unknown error");
        if (error != nullptr)
            g_error_free(error);
        return result;
    }

    if (info->login_options->len == 0) {
        result.errorMessage = QStringLiteral("The gateway did not advertise any login methods.");
        snx_gateway_info_free(info);
        return result;
    }

    for (guint i = 0; i < info->login_options->len; i++) {
        auto *option = static_cast<SnxLoginOption *>(g_ptr_array_index(info->login_options, i));

        result.options.append({QString::fromUtf8(option->id), QString::fromUtf8(option->display_name)});
    }

    result.ok = true;
    snx_gateway_info_free(info);
    return result;
}

const QStringList tunnelTypeOptions = {QStringLiteral("ipsec"), QStringLiteral("ssl")};
const QStringList transportTypeOptions = {QStringLiteral("auto"), QStringLiteral("kernel"), QStringLiteral("udp"), QStringLiteral("tcpt")};

void
setComboValue(QComboBox *combo, const QStringList &options, const QString &value)
{
    int index = value.isEmpty() ? -1 : options.indexOf(value.toLower());

    combo->setCurrentIndex(index >= 0 ? index : 0);
}

} // namespace

SnxSettingWidget::SnxSettingWidget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent)
    : SettingWidget(setting, parent)
    , m_ui(new Ui::SnxWidget)
    , m_setting(setting)
    , m_advancedDialog(new SnxAdvancedWidget(this))
{
    m_ui->setupUi(this);

    m_ui->tunnelType->addItems(tunnelTypeOptions);
    m_ui->transportType->addItems(transportTypeOptions);

    m_ui->password->setPasswordOptionsEnabled(true);
    m_ui->password->setPasswordNotRequiredEnabled(true);
    m_ui->certPassword->setPasswordOptionsEnabled(true);
    m_ui->certPassword->setPasswordNotRequiredEnabled(true);

    setCertificateFieldsVisible(false);

    connect(m_ui->gateway, &QLineEdit::textChanged, this, &SnxSettingWidget::slotWidgetChanged);
    connect(m_ui->queryButton, &QPushButton::clicked, this, &SnxSettingWidget::onQueryClicked);
    connect(m_ui->useCertificate, &QCheckBox::toggled, this, &SnxSettingWidget::onUseCertificateToggled);
    connect(m_ui->certPathBrowse, &QPushButton::clicked, this, &SnxSettingWidget::onCertPathBrowse);
    connect(m_ui->advancedButton, &QPushButton::clicked, this, &SnxSettingWidget::onAdvancedClicked);

    watchChangedSetting();

    KAcceleratorManager::manage(this);

    if (setting && !setting->isNull())
        loadConfig(setting);
}

SnxSettingWidget::~SnxSettingWidget()
{
    delete m_ui;
}

void
SnxSettingWidget::setCertificateFieldsVisible(bool visible)
{
    m_ui->certTypeLabel->setVisible(visible);
    m_ui->certType->setVisible(visible);
    m_ui->certPathLabel->setVisible(visible);
    m_ui->certPath->setVisible(visible);
    m_ui->certPathBrowse->setVisible(visible);
    m_ui->certIdLabel->setVisible(visible);
    m_ui->certId->setVisible(visible);
    m_ui->certPasswordLabel->setVisible(visible);
    m_ui->certPassword->setVisible(visible);
}

QString
SnxSettingWidget::selectedLoginType() const
{
    return m_ui->loginType->currentData().toString();
}

void
SnxSettingWidget::setLoginTypeOptions(const QList<QPair<QString, QString>> &idsAndLabels, const QString &preferredId)
{
    int selectIndex = 0;

    m_ui->loginType->clear();

    if (idsAndLabels.isEmpty()) {
        m_ui->loginType->addItem(QStringLiteral("Use Query... to load login types"), QString());
        return;
    }

    for (int i = 0; i < idsAndLabels.size(); i++) {
        const auto &pair = idsAndLabels.at(i);

        m_ui->loginType->addItem(QStringLiteral("%1 (%2)").arg(pair.second, pair.first), pair.first);
        if (!preferredId.isEmpty() && pair.first == preferredId)
            selectIndex = i;
    }

    m_ui->loginType->setCurrentIndex(selectIndex);
}

void
SnxSettingWidget::onQueryClicked()
{
    const QString server = m_ui->gateway->text();

    if (server.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("Query login types"), QStringLiteral("Enter the gateway address first."));
        return;
    }

    m_ui->queryButton->setEnabled(false);

    auto *watcher = new QFutureWatcher<SnxQueryResult>(this);
    connect(watcher, &QFutureWatcher<SnxQueryResult>::finished, this, [this, watcher]() {
        const SnxQueryResult result = watcher->result();

        watcher->deleteLater();
        m_ui->queryButton->setEnabled(true);

        if (!result.ok) {
            QMessageBox::warning(this, QStringLiteral("Query login types"), result.errorMessage);
            return;
        }

        const QString previous = selectedLoginType();

        setLoginTypeOptions(result.options, previous);
    });

    const bool ignoreCert = m_advancedData.value(QLatin1String(NM_SNX_KEY_IGNORE_SERVER_CERT)) == QLatin1String("true");
    watcher->setFuture(QtConcurrent::run(snxRunQuery, server, ignoreCert));
}

void
SnxSettingWidget::onUseCertificateToggled(bool checked)
{
    setCertificateFieldsVisible(checked);
}

void
SnxSettingWidget::onCertPathBrowse()
{
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Client Certificate"));

    if (!path.isEmpty())
        m_ui->certPath->setText(path);
}

void
SnxSettingWidget::onAdvancedClicked()
{
    m_advancedDialog->loadConfig(m_advancedData);

    connect(m_advancedDialog, &QDialog::accepted, this, [this]() {
        m_advancedData.insert(m_advancedDialog->setting());
        emit settingChanged();
    }, Qt::UniqueConnection);

    m_advancedDialog->setModal(true);
    m_advancedDialog->show();
}

void
SnxSettingWidget::loadConfig(const NetworkManager::Setting::Ptr &setting)
{
    Q_UNUSED(setting);

    const NMStringMap data = m_setting->data();

    m_advancedData = data;

    m_ui->gateway->setText(data.value(QLatin1String(NM_SNX_KEY_SERVER_NAME)));
    setComboValue(m_ui->tunnelType, tunnelTypeOptions, data.value(QLatin1String(NM_SNX_KEY_TUNNEL_TYPE)));
    setComboValue(m_ui->transportType, transportTypeOptions, data.value(QLatin1String(NM_SNX_KEY_TRANSPORT_TYPE)));

    const QString loginType = data.value(QLatin1String(NM_SNX_KEY_LOGIN_TYPE));
    if (!loginType.isEmpty())
        setLoginTypeOptions({{loginType, loginType}}, loginType);
    else
        setLoginTypeOptions({}, QString());

    m_ui->user->setText(m_setting->username());

    const QString certType = data.value(QLatin1String(NM_SNX_KEY_CERT_TYPE));
    const QString certPath = data.value(QLatin1String(NM_SNX_KEY_CERT_PATH));
    const QString certId = data.value(QLatin1String(NM_SNX_KEY_CERT_ID));
    const bool useCertificate = !certType.isEmpty() || !certPath.isEmpty() || !certId.isEmpty();

    m_ui->certType->setText(certType);
    m_ui->certPath->setText(certPath);
    m_ui->certId->setText(certId);
    m_ui->useCertificate->setChecked(useCertificate);
    setCertificateFieldsVisible(useCertificate);

    const auto passwordFlags =
        static_cast<NetworkManager::Setting::SecretFlags>(data.value(QLatin1String(NM_SNX_KEY_PASSWORD "-flags")).toInt());
    if (passwordFlags.testFlag(NetworkManager::Setting::None))
        m_ui->password->setPasswordOption(PasswordField::StoreForAllUsers);
    else if (passwordFlags.testFlag(NetworkManager::Setting::NotSaved))
        m_ui->password->setPasswordOption(PasswordField::AlwaysAsk);
    else if (passwordFlags.testFlag(NetworkManager::Setting::NotRequired))
        m_ui->password->setPasswordOption(PasswordField::NotRequired);
    else
        m_ui->password->setPasswordOption(PasswordField::StoreForUser);

    const auto certPasswordFlags =
        static_cast<NetworkManager::Setting::SecretFlags>(data.value(QLatin1String(NM_SNX_KEY_CERT_PASSWORD "-flags")).toInt());
    if (certPasswordFlags.testFlag(NetworkManager::Setting::None))
        m_ui->certPassword->setPasswordOption(PasswordField::StoreForAllUsers);
    else if (certPasswordFlags.testFlag(NetworkManager::Setting::NotSaved))
        m_ui->certPassword->setPasswordOption(PasswordField::AlwaysAsk);
    else if (certPasswordFlags.testFlag(NetworkManager::Setting::NotRequired))
        m_ui->certPassword->setPasswordOption(PasswordField::NotRequired);
    else
        m_ui->certPassword->setPasswordOption(PasswordField::StoreForUser);

    loadSecrets(setting);
}

void
SnxSettingWidget::loadSecrets(const NetworkManager::Setting::Ptr &setting)
{
    NetworkManager::VpnSetting::Ptr vpnSetting = setting.staticCast<NetworkManager::VpnSetting>();

    if (!vpnSetting)
        return;

    const NMStringMap secrets = vpnSetting->secrets();
    const QString password = secrets.value(QLatin1String(NM_SNX_KEY_PASSWORD));
    const QString certPassword = secrets.value(QLatin1String(NM_SNX_KEY_CERT_PASSWORD));

    if (!password.isEmpty())
        m_ui->password->setText(password);
    if (!certPassword.isEmpty())
        m_ui->certPassword->setText(certPassword);
}

namespace
{

void
insertPasswordFlags(NMStringMap &data, const char *key, PasswordField::PasswordOption option)
{
    NetworkManager::Setting::SecretFlags flags;

    switch (option) {
    case PasswordField::StoreForAllUsers:
        flags = NetworkManager::Setting::None;
        break;
    case PasswordField::AlwaysAsk:
        flags = NetworkManager::Setting::NotSaved;
        break;
    case PasswordField::NotRequired:
        flags = NetworkManager::Setting::NotRequired;
        break;
    case PasswordField::StoreForUser:
    default:
        flags = NetworkManager::Setting::AgentOwned;
        break;
    }

    data.insert(QLatin1String(key), QString::number(static_cast<int>(flags)));
}

} // namespace

QVariantMap
SnxSettingWidget::setting() const
{
    NetworkManager::VpnSetting setting;
    NMStringMap data = m_advancedData;
    NMStringMap secrets;
    const bool useCertificate = m_ui->useCertificate->isChecked();

    setting.setServiceType(QLatin1String(NM_DBUS_SERVICE_SNX));
    setting.setUsername(m_ui->user->text());

    if (!m_ui->gateway->text().isEmpty())
        data.insert(QLatin1String(NM_SNX_KEY_SERVER_NAME), m_ui->gateway->text());
    else
        data.remove(QLatin1String(NM_SNX_KEY_SERVER_NAME));

    const QString loginType = selectedLoginType();
    if (!loginType.isEmpty())
        data.insert(QLatin1String(NM_SNX_KEY_LOGIN_TYPE), loginType);
    else
        data.remove(QLatin1String(NM_SNX_KEY_LOGIN_TYPE));

    data.insert(QLatin1String(NM_SNX_KEY_TUNNEL_TYPE), m_ui->tunnelType->currentText());
    data.insert(QLatin1String(NM_SNX_KEY_TRANSPORT_TYPE), m_ui->transportType->currentText());

    if (useCertificate) {
        data.insert(QLatin1String(NM_SNX_KEY_CERT_TYPE), m_ui->certType->text());
        data.insert(QLatin1String(NM_SNX_KEY_CERT_PATH), m_ui->certPath->text());
        data.insert(QLatin1String(NM_SNX_KEY_CERT_ID), m_ui->certId->text());
    } else {
        data.remove(QLatin1String(NM_SNX_KEY_CERT_TYPE));
        data.remove(QLatin1String(NM_SNX_KEY_CERT_PATH));
        data.remove(QLatin1String(NM_SNX_KEY_CERT_ID));
    }

    if (!m_ui->password->text().isEmpty())
        secrets.insert(QLatin1String(NM_SNX_KEY_PASSWORD), m_ui->password->text());
    insertPasswordFlags(data, NM_SNX_KEY_PASSWORD "-flags", m_ui->password->passwordOption());

    if (useCertificate) {
        if (!m_ui->certPassword->text().isEmpty())
            secrets.insert(QLatin1String(NM_SNX_KEY_CERT_PASSWORD), m_ui->certPassword->text());
        insertPasswordFlags(data, NM_SNX_KEY_CERT_PASSWORD "-flags", m_ui->certPassword->passwordOption());
    } else {
        data.insert(QLatin1String(NM_SNX_KEY_CERT_PASSWORD "-flags"), QString::number(static_cast<int>(NetworkManager::Setting::NotRequired)));
    }

    setting.setData(data);
    setting.setSecrets(secrets);
    return setting.toMap();
}

bool
SnxSettingWidget::isValid() const
{
    return !m_ui->gateway->text().isEmpty();
}

#include "moc_snxwidget.cpp"
