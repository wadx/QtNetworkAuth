/****************************************************************************
**
** Copyright (C) 2017 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the Qt Network Auth module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:GPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3 or (at your option) any later version
** approved by the KDE Free Qt Foundation. The licenses are as published by
** the Free Software Foundation and appearing in the file LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#pragma once

#include "QAbstractOAuth2.h"

QT_BEGIN_NAMESPACE

class QUrl;
class QString;
class QNetworkAccessManager;


class QOAuth2AuthorizationCodeFlow : public QAbstractOAuth2
{
	Q_OBJECT
	Q_DISABLE_COPY(QOAuth2AuthorizationCodeFlow)

	Q_PROPERTY(QUrl accessTokenUrl READ accessTokenUrl WRITE setAccessTokenUrl NOTIFY accessTokenUrlChanged)
public:
	QOAuth2AuthorizationCodeFlow(const QUrl& authorizationUrl, const QUrl& accessTokenUrl, const QString& clientIdentifier, QNetworkAccessManager* manager, QObject* parent = nullptr);
	explicit QOAuth2AuthorizationCodeFlow(QObject* parent = nullptr);
	explicit QOAuth2AuthorizationCodeFlow(QNetworkAccessManager* manager, QObject* parent = nullptr);
	QOAuth2AuthorizationCodeFlow(const QString& clientIdentifier, QNetworkAccessManager* manager, QObject* parent = nullptr);
	QOAuth2AuthorizationCodeFlow(const QUrl& authorizationUrl, const QUrl& accessTokenUrl, QNetworkAccessManager* manager, QObject* parent = nullptr);
	~QOAuth2AuthorizationCodeFlow();

	QUrl accessTokenUrl() const;
	void setAccessTokenUrl(const QUrl& accessTokenUrl);

public Q_SLOTS:
	void grant() override;
	void refreshAccessToken();

protected:
	QUrl buildAuthenticateUrl(const QMultiMap<QString, QVariant>& parameters = {});
	void requestAccessToken(const QString& code);
	void resourceOwnerAuthorization(const QUrl& url,
		const QMultiMap<QString, QVariant>& parameters = {}) override;

Q_SIGNALS:
	void accessTokenUrlChanged(const QUrl& accessTokenUrl);

private:
	void _q_handleCallback(const QVariantMap& data);
	void _q_accessTokenRequestFinished(const QVariantMap& values);
	void _q_authenticate(QNetworkReply* reply, QAuthenticator* authenticator);

	QUrl                    _accessTokenUrl;
	QString                 _tokenType;
	QPointer<QNetworkReply> _currentReply;
};

QT_END_NAMESPACE

