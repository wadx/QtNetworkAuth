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

#include <QtCore/qdatetime.h>
#include "QAbstractAOuth.h"

QT_BEGIN_NAMESPACE

class QHttpMultiPart;


class QAbstractOAuth2 : public QAbstractOAuth
{
	Q_OBJECT
		Q_PROPERTY(QString scope READ scope WRITE setScope NOTIFY scopeChanged)
		Q_PROPERTY(QString userAgent READ userAgent WRITE setUserAgent NOTIFY userAgentChanged)
		Q_PROPERTY(QString clientIdentifierSharedKey READ clientIdentifierSharedKey WRITE setClientIdentifierSharedKey NOTIFY clientIdentifierSharedKeyChanged)
		Q_PROPERTY(QString state READ state WRITE setState NOTIFY stateChanged)
		Q_PROPERTY(QDateTime expiration READ expirationAt NOTIFY expirationAtChanged)
		Q_PROPERTY(QString refreshToken READ refreshToken WRITE setRefreshToken NOTIFY refreshTokenChanged)

public:
	Q_INVOKABLE virtual QUrl createAuthenticatedUrl(const QUrl& url, const QVariantMap& parameters = QVariantMap());
	Q_INVOKABLE QNetworkReply* head(const QUrl& url, const QVariantMap& parameters = QVariantMap()) override;
	Q_INVOKABLE QNetworkReply* get(const QUrl& url, const QVariantMap& parameters = QVariantMap()) override;
	Q_INVOKABLE QNetworkReply* post(const QUrl& url, const QVariantMap& parameters = QVariantMap()) override;
	Q_INVOKABLE virtual QNetworkReply* post(const QUrl& url, const QByteArray& data);
	Q_INVOKABLE virtual QNetworkReply* post(const QUrl& url, QHttpMultiPart* multiPart);
	Q_INVOKABLE QNetworkReply* put(const QUrl& url, const QVariantMap& parameters = QVariantMap()) override;
	Q_INVOKABLE virtual QNetworkReply* put(const QUrl& url, const QByteArray& data);
	Q_INVOKABLE virtual QNetworkReply* put(const QUrl& url, QHttpMultiPart* multiPart);
	Q_INVOKABLE QNetworkReply* deleteResource(const QUrl& url, const QVariantMap& parameters = QVariantMap()) override;

	explicit QAbstractOAuth2(const QPair<QString, QString>& clientCredentials, const QUrl& authorizationUrl, QNetworkAccessManager* manager, QObject* parent = nullptr);
	explicit QAbstractOAuth2(QObject* parent = nullptr);
	explicit QAbstractOAuth2(QNetworkAccessManager* manager, QObject* parent = nullptr);
	~QAbstractOAuth2();

	QString scope() const;
	void setScope(const QString& scope);
	QString userAgent() const;
	void setUserAgent(const QString& userAgent);
	QString responseType() const;
	QString clientIdentifierSharedKey() const;
	void setClientIdentifierSharedKey(const QString& clientIdentifierSharedKey);
	QString state() const;
	void setState(const QString& state);
	QDateTime expirationAt() const;
	QString refreshToken() const;
	void setRefreshToken(const QString& refreshToken);
	void prepareRequest(QNetworkRequest* request, const QByteArray& verb, const QByteArray& body = QByteArray()) override;

Q_SIGNALS:
	void scopeChanged(const QString& scope);
	void userAgentChanged(const QString& userAgent);
	void responseTypeChanged(const QString& responseType);
	void clientIdentifierSharedKeyChanged(const QString& clientIdentifierSharedKey);
	void stateChanged(const QString& state);
	void expirationAtChanged(const QDateTime& expiration);
	void refreshTokenChanged(const QString& refreshToken);
	void error(const QString& error, const QString& errorDescription, const QUrl& uri);
	void authorizationCallbackReceived(const QVariantMap& data);

protected:
	void setResponseType(const QString& responseType);

public:
	static QString generateRandomState();
	QNetworkRequest createRequest(QUrl url, const QVariantMap* parameters = nullptr);

	QString       _clientIdentifierSharedKey;
	QString       _scope;
	QString       _state = generateRandomState();
	QString       _userAgent = QStringLiteral("QtOAuth/1.0 (+https://www.qt.io)");
	QString       _responseType;
	const QString _bearerFormat = QStringLiteral("Bearer %1"); // Case sensitive
	QDateTime     _expiresAt;
	QString       _refreshToken;

	struct OAuth2KeyString
	{
		static const QString accessToken;
		static const QString apiKey;
		static const QString clientIdentifier;
		static const QString clientSharedSecret;
		static const QString code;
		static const QString error;
		static const QString errorDescription;
		static const QString errorUri;
		static const QString expiresIn;
		static const QString grantType;
		static const QString redirectUri;
		static const QString refreshToken;
		static const QString responseType;
		static const QString scope;
		static const QString state;
		static const QString tokenType;
	};
};

QT_END_NAMESPACE

