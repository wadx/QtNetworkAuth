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

#include "QAbstractAOuth.h"

#include <QtNetwork/qnetworkaccessmanager.h>

QT_BEGIN_NAMESPACE

class QOAuth1Signature;


class QOAuth1 : public QAbstractOAuth
{
	Q_OBJECT

public:
	enum class SignatureMethod {
		Hmac_Sha1,
		Rsa_Sha1,
		PlainText
	};

	Q_ENUM(SignatureMethod)

	explicit QOAuth1(QObject* parent = nullptr);
	explicit QOAuth1(QNetworkAccessManager* manager, QObject* parent = nullptr);
	QOAuth1(const QPair<QString, QString>& clientCredentials, QNetworkAccessManager* networkAccessManager = nullptr);
	QOAuth1(const QString& clientIdentifier, const QString& clientSharedSecret, QNetworkAccessManager* manager, QObject* parent = nullptr);

	QString clientSharedSecret() const;
	void setClientSharedSecret(const QString& clientSharedSecret);
	QPair<QString, QString> clientCredentials() const;
	void setClientCredentials(const QPair<QString, QString>& clientCredentials);
	void setClientCredentials(const QString& clientIdentifier, const QString& clientSharedSecret);

	// Token credentials: https://tools.ietf.org/html/rfc5849#section-2.3
	QString tokenSecret() const;
	void setTokenSecret(const QString& tokenSecret);
	QPair<QString, QString> tokenCredentials() const;
	void setTokenCredentials(const QPair<QString, QString>& tokenCredentials);
	void setTokenCredentials(const QString& token, const QString& tokenSecret);

	// Temporary Credentials: https://tools.ietf.org/html/rfc5849#section-2.1
	QUrl temporaryCredentialsUrl() const;
	void setTemporaryCredentialsUrl(const QUrl& url);

	// Token Credentials: https://tools.ietf.org/html/rfc5849#section-2.3
	QUrl tokenCredentialsUrl() const;
	void setTokenCredentialsUrl(const QUrl& url);

	// Signature method: https://tools.ietf.org/html/rfc5849#section-3.4
	SignatureMethod signatureMethod() const;
	void setSignatureMethod(SignatureMethod value);

	void prepareRequest(QNetworkRequest* request, const QByteArray& verb,
		const QByteArray& body = QByteArray()) override;

	QNetworkReply* head(const QUrl& url, const QVariantMap& parameters = QVariantMap()) override;
	QNetworkReply* get(const QUrl& url, const QVariantMap& parameters = QVariantMap()) override;

	QNetworkReply* post(const QUrl& url, const QVariantMap& parameters = QVariantMap()) override;
	QNetworkReply* put(const QUrl& url, const QVariantMap& parameters = QVariantMap()) override;
	QNetworkReply* deleteResource(const QUrl& url,
		const QVariantMap& parameters = QVariantMap()) override;

public Q_SLOTS:
	void grant() override;
	void continueGrantWithVerifier(const QString& verifier);

Q_SIGNALS:
	void signatureMethodChanged(QOAuth1::SignatureMethod method);
	void clientSharedSecretChanged(const QString& credential);
	void tokenSecretChanged(const QString& token);
	void temporaryCredentialsUrlChanged(const QUrl& url);
	void tokenCredentialsUrlChanged(const QUrl& url);

protected:
	QNetworkReply* requestTemporaryCredentials(QNetworkAccessManager::Operation operation, const QUrl& url, const QVariantMap& parameters = QVariantMap());
	QNetworkReply* requestTokenCredentials(QNetworkAccessManager::Operation operation, const QUrl& url, const QPair<QString, QString>& temporaryToken, const QVariantMap& parameters = QVariantMap());
	void setup(QNetworkRequest* request, const QVariantMap& signingParameters, QNetworkAccessManager::Operation operation);
	void setup(QNetworkRequest* request, const QVariantMap& signingParameters, const QByteArray& operationVerb);
	static QByteArray nonce();
	static QByteArray generateAuthorizationHeader(const QVariantMap& oauthParams);

private:
	Q_DISABLE_COPY(QOAuth1)

public:
	void appendCommonHeaders(QVariantMap* headers);
	void appendSignature(QAbstractOAuth::Stage stage, QVariantMap* headers, const QUrl& url, QNetworkAccessManager::Operation operation, const QMultiMap<QString, QVariant> parameters);
	QNetworkReply* requestToken(QNetworkAccessManager::Operation operation, const QUrl& url, const QPair<QString, QString>& token, const QVariantMap& additionalParameters);
	QString signatureMethodString() const;
	QByteArray generateSignature(const QMultiMap<QString, QVariant>& parameters, const QUrl& url, QNetworkAccessManager::Operation operation) const;
	QByteArray generateSignature(const QMultiMap<QString, QVariant>& parameters, const QUrl& url, const QByteArray& verb) const;
	QByteArray formatSignature(const QOAuth1Signature& signature) const;
	QVariantMap createOAuthBaseParams() const;

	void _q_onTokenRequestError(QNetworkReply::NetworkError error);
	void _q_tokensReceived(const QVariantMap& tokens);

	QString         _clientIdentifierSharedKey;
	QString         _tokenSecret;
	QString         _verifier;
	QUrl            _temporaryCredentialsUrl;
	QUrl            _tokenCredentialsUrl;
	SignatureMethod _signatureMethod = QOAuth1::SignatureMethod::Hmac_Sha1;
	const QString   _oauthVersion = QStringLiteral("1.0");
	bool            _tokenRequested = false;

	struct OAuth1KeyString
	{
		static const QString oauthCallback;
		static const QString oauthCallbackConfirmed;
		static const QString oauthConsumerKey;
		static const QString oauthNonce;
		static const QString oauthSignature;
		static const QString oauthSignatureMethod;
		static const QString oauthTimestamp;
		static const QString oauthToken;
		static const QString oauthTokenSecret;
		static const QString oauthVerifier;
		static const QString oauthVersion;
	};
};

QT_END_NAMESPACE

