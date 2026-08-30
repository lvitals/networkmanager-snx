/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNXADVANCEDWIDGET_H
#define SNXADVANCEDWIDGET_H

#include <QDialog>

#include <NetworkManagerQt/GenericTypes>

namespace Ui
{
class SnxAdvancedWidget;
}

/* Interface name/MTU, DNS, routing, CA certificate, and IPsec session
 * options: the same fields as the GTK editor's "Advanced Settings" dialog
 * (src/nm-snx-editor.c: build_advanced_dialog()). Operates on a plain
 * key/value NMStringMap rather than a whole VpnSetting so SnxSettingWidget
 * can snapshot/merge it independently of the fields the main widget owns. */
class SnxAdvancedWidget : public QDialog
{
    Q_OBJECT
public:
    explicit SnxAdvancedWidget(QWidget *parent = nullptr);
    ~SnxAdvancedWidget() override;

    void loadConfig(const NMStringMap &data);
    NMStringMap setting() const;

private:
    Ui::SnxAdvancedWidget *const m_ui;
};

#endif // SNXADVANCEDWIDGET_H
