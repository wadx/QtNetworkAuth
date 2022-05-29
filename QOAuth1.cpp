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

#include "stdafx.h"
#include "QOAuth1.h"
#include "QOAuth1Signature.h"
#include "QOAuthOobReplyHandler.h"
#include "QOAuthHttpServerReplyHandler.h"
#include <QtCore/qmap.h>
#include <QtCore/qlist.h>
#include <QtCore/qvariant.h>
#include <QtCore/qurlquery.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qmessageauthenticationcode.h>
#include <QtNetwork/qnetworkreply.h>
#include <QtNetwork/qnetworkrequest.h>
#include <QtNetwork/qnetworkaccessmanager.h>
#include "moc_QOAuth1.cpp"

QT_BEGIN_NAMESPACE

Q_DECLARE_LOGGING_CATEGORY(NetworkAuthLogging)

using Key = QOAuth1::OAuth1KeyString;
const QString Key::oauthCallback = QStringLiteral("oauth_callback");
const QString Key::oauthCallbackConfirmed = QStringLiteral("oauth_callback_confirmed");
const QString Key::oauthConsumerKey = QStringLiteral("oauth_consumer_key");
const QString Key::oauthNonce = QStringLiteral("oauth_nonce");
const QString Key::oauthSignature = QStringLiteral("oauth_signature");
const QString Key::oauthSignatureMethod = QStringLiteral("oauth_signature_method");
const QString Key::oauthTimestamp = QStringLiteral("oauth_timestamp");
const QString Key::oauthToken = QStringLiteral("oauth_token");
const QString Key::oauthTokenSecret = QStringLiteral("oauth_token_secret");
const QString Key::oauthVerifier = QStringLiteral("oauth_verifier");
const QString Key::oauthVersion = QStringLiteral("oauth_version");


QOAuth1::QOAuth1(const QPair<QString, QString>& clientCredentials, QNetworkAccessManager* networkAccessManager)
	: QAbstractOAuth(QUrl(), clientCredentials.first, networkAccessManager)
	, _clientIdentifierSharedKey(clientCredentials.second)
{
	qRegisterMetaType<QNetworkReply::NetworkError>("QNetworkReply::NetworkError");
	qRegisterMetaType<QOAuth1::SignatureMethod>("QOAuth1::SignatureMethod");
}


QOAuth1::QOAuth1(QObject* parent)
	: QOAuth1(nullptr, parent)
{}


QOAuth1::QOAuth1(QNetworkAccessManager* manager, QObject* parent)
	: QOAuth1(QString(), QString(), manager, parent)
{}


QOAuth1::QOAuth1(const QString& clientIdentifier, const QString& clientSharedSecret, QNetworkAccessManager* manager, QObject* parent)
	: QAbstractOAuth(QUrl(), clientIdentifier, manager, parent)
	, _clientIdentifierSharedKey(clientSharedSecret)
{}



void QOAuth1::appendCommonHeaders(QVariantMap* headers)
{
	const auto currentDateTime = QDateTime::currentDateTimeUtc();

	headers->insert(Key::oauthNonce, QOAuth1::nonce());
	headers->insert(Key::oauthConsumerKey, _clientIdentifier);
	headers->insert(Key::oauthTimestamp, QString::number(currentDateTime.toSecsSinceEpoch()));
	headers->insert(Key::oauthVersion, _oauthVersion);
	headers->insert(Key::oauthSignatureMethod, signatureMethodString().toUtf8());
}


void QOAuth1::appendSignature(QAbstractOAuth::Stage stage, QVariantMap* headers, const QUrl& url, QNetworkAccessManager::Operation operation, const QMultiMap<QString, QVariant> parameters)
{
	QByteArray signature;
	{
		QMultiMap<QString, QVariant> allParameters(*headers);
		allParameters.unite(parameters);
		if (_modifyParametersFunction)
		{
			_modifyParametersFunction(stage, &allParameters);
		}
		signature = generateSignature(allParameters, url, operation);
	}
	headers->insert(Key::oauthSignature, signature);
}


QNetworkReply* QOAuth1::requestToken(QNetworkAccessManager::Operation operation, const QUrl& url, const QPair<QString, QString>& token, const QVariantMap& parameters)
{
	if (Q_UNLIKELY(!networkAccessManager()))
	{
		qCWarning(NetworkAuthLogging, "QNetworkAccessManager not available");
		return nullptr;
	}
	if (Q_UNLIKELY(url.isEmpty()))
	{
		qCWarning(NetworkAuthLogging, "Request Url not set");
		return nullptr;
	}
	if (Q_UNLIKELY(operation != QNetworkAccessManager::GetOperation && operation != QNetworkAccessManager::PostOperation))
	{
		qCWarning(NetworkAuthLogging, "Operation not supported");
		return nullptr;
	}

	QNetworkRequest request(url);

	QAbstractOAuth::Stage stage = QAbstractOAuth::Stage::RequestingTemporaryCredentials;
	QVariantMap headers;
	QMultiMap<QString, QVariant> remainingParameters;
	appendCommonHeaders(&headers);
	for (auto it = parameters.begin(), end = parameters.end(); it != end; ++it)
	{
		const auto key = it.key();
		const auto value = it.value();
		if (key.startsWith(QStringLiteral("oauth_")))
		{
			headers.insert(key, value);
		}
		else
		{
			remainingParameters.insert(key, value);
		}
	}
	if (!token.first.isEmpty())
	{
		headers.insert(Key::oauthToken, token.first);
		stage = QAbstractOAuth::Stage::RequestingAccessToken;
	}
	appendSignature(stage, &headers, url, operation, remainingParameters);

	request.setRawHeader("Authorization", QOAuth1::generateAuthorizationHeader(headers));

	QNetworkReply* reply = nullptr;
	if (operation == QNetworkAccessManager::GetOperation)
	{
		if (parameters.size() > 0)
		{
			QUrl url = request.url();
			url.setQuery(QOAuth1::createQuery(remainingParameters));
			request.setUrl(url);
		}
		reply = networkAccessManager()->get(request);
	}
	else if (operation == QNetworkAccessManager::PostOperation)
	{
		QUrlQuery query = QOAuth1::createQuery(remainingParameters);
		const QByteArray data = query.toString(QUrl::FullyEncoded).toUtf8();
		request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));
		reply = networkAccessManager()->post(request, data);
	}

	connect(reply, &QNetworkReply::errorOccurred, this, &QOAuth1::_q_onTokenRequestError);

	QAbstractOAuthReplyHandler* handler = _replyHandler ? _replyHandler.data() : _defaultReplyHandler.data();
	QObject::connect(reply, &QNetworkReply::finished, [handler, reply]()
	{
		handler->networkReplyFinished(reply);
	});
	connect(handler, &QAbstractOAuthReplyHandler::tokensReceived, this, &QOAuth1::_q_tokensReceived);

	return reply;
}

QString QOAuth1::signatureMethodString() const
{
	switch (_signatureMethod)
	{ // No default: intended
	case QOAuth1::SignatureMethod::PlainText:
		return QStringLiteral("PLAINTEXT");
	case QOAuth1::SignatureMethod::Hmac_Sha1:
		return QStringLiteral("HMAC-SHA1");
	case QOAuth1::SignatureMethod::Rsa_Sha1:
		qFatal("RSA-SHA1 signature method not supported");
		return QStringLiteral("RSA-SHA1");
	}
	qFatal("Invalid signature method");
	return QString();
}


QByteArray QOAuth1::generateSignature(const QMultiMap<QString, QVariant>& parameters, const QUrl& url, QNetworkAccessManager::Operation operation) const
{
	QOAuth1Signature signature(url, _clientIdentifierSharedKey, _tokenSecret, static_cast<QOAuth1Signature::HttpRequestMethod>(operation), parameters);
	return formatSignature(signature);
}


QByteArray QOAuth1::generateSignature(const QMultiMap<QString, QVariant>& parameters, const QUrl& url, const QByteArray& verb) const
{
	QOAuth1Signature signature(url, _clientIdentifierSharedKey, _tokenSecret, QOAuth1Signature::HttpRequestMethod::Custom, parameters);
	signature.setCustomMethodString(verb);
	return formatSignature(signature);
}


QByteArray QOAuth1::formatSignature(const QOAuth1Signature& signature) const
{
	switch (_signatureMethod)
	{
	case QOAuth1::SignatureMethod::Hmac_Sha1:
		return signature.hmacSha1().toBase64();
	case QOAuth1::SignatureMethod::PlainText:
		return signature.plainText();
	default:
		qFatal("QOAuth1::generateSignature: Signature method not supported");
		return QByteArray();
	}
}

QVariantMap QOAuth1::createOAuthBaseParams() const
{
	QVariantMap oauthParams;
	const auto currentDateTime = QDateTime::currentDateTimeUtc();
	oauthParams.insert(Key::oauthConsumerKey, _clientIdentifier);
	oauthParams.insert(Key::oauthVersion, QStringLiteral("1.0"));
	oauthParams.insert(Key::oauthToken, _token);
	oauthParams.insert(Key::oauthSignatureMethod, signatureMethodString());
	oauthParams.insert(Key::oauthNonce, QOAuth1::nonce());
	oauthParams.insert(Key::oauthTimestamp, QString::number(currentDateTime.toSecsSinceEpoch()));
	return oauthParams;
}


void QOAuth1::prepareRequest(QNetworkRequest* request, const QByteArray& verb, const QByteArray& body)
{
	QVariantMap signingParams;
	if (verb == "POST" && request->header(QNetworkRequest::ContentTypeHeader).toByteArray() == "application/x-www-form-urlencoded")
	{
		QUrlQuery query(QString::fromUtf8(body));
		for (const auto& item : query.queryItems(QUrl::FullyDecoded))
		{
			signingParams.insert(item.first, item.second);
		}
	}
	setup(request, signingParams, verb);
}


void QOAuth1::_q_onTokenRequestError(QNetworkReply::NetworkError error)
{
	Q_UNUSED(error);
	Q_EMIT requestFailed(QAbstractOAuth::Error::NetworkError);
}


void QOAuth1::_q_tokensReceived(const QVariantMap& tokens)
{
	if (!_tokenRequested && _status == QAbstractOAuth::Status::TemporaryCredentialsReceived)
	{
		// We didn't request a token yet, but in the "TemporaryCredentialsReceived" state _any_
		// new tokens received will count as a successful authentication and we move to the
		// 'Granted' state. To avoid this, 'status' will be temporarily set to 'NotAuthenticated'.
		_status = QAbstractOAuth::Status::NotAuthenticated;
	}
	if (_tokenRequested) // 'Reset' tokenRequested now that we've gotten new tokens
	{
		_tokenRequested = false;
	}
	QPair<QString, QString> credential(tokens.value(Key::oauthToken).toString(),
		tokens.value(Key::oauthTokenSecret).toString());
	switch (_status)
	{
	case QAbstractOAuth::Status::NotAuthenticated:
		if (tokens.value(Key::oauthCallbackConfirmed, true).toBool())
		{
			setTokenCredentials(credential);
			setStatus(QAbstractOAuth::Status::TemporaryCredentialsReceived);
		}
		else
		{
			Q_EMIT requestFailed(QAbstractOAuth::Error::OAuthCallbackNotVerified);
		}
		break;
	case QAbstractOAuth::Status::TemporaryCredentialsReceived:
		setTokenCredentials(credential);
		setStatus(QAbstractOAuth::Status::Granted);
		break;
	case QAbstractOAuth::Status::Granted:
	case QAbstractOAuth::Status::RefreshingToken:
		break;
	}
}


QString QOAuth1::clientSharedSecret() const
{
	return _clientIdentifierSharedKey;
}


void QOAuth1::setClientSharedSecret(const QString& clientSharedSecret)
{
	if (_clientIdentifierSharedKey != clientSharedSecret)
	{
		_clientIdentifierSharedKey = clientSharedSecret;
		Q_EMIT clientSharedSecretChanged(clientSharedSecret);
	}
}


QPair<QString, QString> QOAuth1::clientCredentials() const
{
	return qMakePair(_clientIdentifier, _clientIdentifierSharedKey);
}


void QOAuth1::setClientCredentials(const QPair<QString, QString>& clientCredentials)
{
	setClientCredentials(clientCredentials.first, clientCredentials.second);
}


void QOAuth1::setClientCredentials(const QString& clientIdentifier, const QString& clientSharedSecret)
{
	setClientIdentifier(clientIdentifier);
	setClientSharedSecret(clientSharedSecret);
}


QString QOAuth1::tokenSecret() const
{
	return _tokenSecret;
}


void QOAuth1::setTokenSecret(const QString& tokenSecret)
{
	if (_tokenSecret != tokenSecret)
	{
		_tokenSecret = tokenSecret;
		Q_EMIT tokenSecretChanged(tokenSecret);
	}
}


QPair<QString, QString> QOAuth1::tokenCredentials() const
{
	return qMakePair(_token, _tokenSecret);
}


void QOAuth1::setTokenCredentials(const QPair<QString, QString>& tokenCredentials)
{
	setTokenCredentials(tokenCredentials.first, tokenCredentials.second);
}


void QOAuth1::setTokenCredentials(const QString& token, const QString& tokenSecret)
{
	setToken(token);
	setTokenSecret(tokenSecret);
}


QUrl QOAuth1::temporaryCredentialsUrl() const
{
	return _temporaryCredentialsUrl;
}


void QOAuth1::setTemporaryCredentialsUrl(const QUrl& url)
{
	if (_temporaryCredentialsUrl != url)
	{
		_temporaryCredentialsUrl = url;
		Q_EMIT temporaryCredentialsUrlChanged(url);
	}
}


QUrl QOAuth1::tokenCredentialsUrl() const
{
	return _tokenCredentialsUrl;
}


void QOAuth1::setTokenCredentialsUrl(const QUrl& url)
{
	if (_tokenCredentialsUrl != url)
	{
		_tokenCredentialsUrl = url;
		Q_EMIT tokenCredentialsUrlChanged(url);
	}
}


QOAuth1::SignatureMethod QOAuth1::signatureMethod() const
{
	return _signatureMethod;
}


void QOAuth1::setSignatureMethod(QOAuth1::SignatureMethod value)
{
	if (_signatureMethod != value)
	{
		_signatureMethod = value;
		Q_EMIT signatureMethodChanged(value);
	}
}


QNetworkReply* QOAuth1::head(const QUrl& url, const QVariantMap& parameters)
{
	if (!networkAccessManager())
	{
		qCWarning(NetworkAuthLogging, "QNetworkAccessManager not available");
		return nullptr;
	}
	QNetworkRequest request(url);
	setup(&request, parameters, QNetworkAccessManager::HeadOperation);
	return networkAccessManager()->head(request);
}


QNetworkReply* QOAuth1::get(const QUrl& url, const QVariantMap& parameters)
{
	if (!networkAccessManager())
	{
		qCWarning(NetworkAuthLogging, "QNetworkAccessManager not available");
		return nullptr;
	}
	QNetworkRequest request(url);
	setup(&request, parameters, QNetworkAccessManager::GetOperation);
	QNetworkReply* reply = networkAccessManager()->get(request);
	connect(reply, &QNetworkReply::finished, [this, reply]()
	{
		emit finished(reply);
	});
	return reply;
}


QNetworkReply* QOAuth1::post(const QUrl& url, const QVariantMap& parameters)
{
	if (!networkAccessManager())
	{
		qCWarning(NetworkAuthLogging, "QNetworkAccessManager not available");
		return nullptr;
	}
	QNetworkRequest request(url);
	setup(&request, parameters, QNetworkAccessManager::PostOperation);
	addContentTypeHeaders(&request);

	const QByteArray data = convertParameters(parameters);
	QNetworkReply* reply = networkAccessManager()->post(request, data);
	connect(reply, &QNetworkReply::finished, [this, reply]() { emit finished(reply); });
	return reply;
}


QNetworkReply* QOAuth1::put(const QUrl& url, const QVariantMap& parameters)
{
	if (!networkAccessManager())
	{
		qCWarning(NetworkAuthLogging, "QNetworkAccessManager not available");
		return nullptr;
	}
	QNetworkRequest request(url);
	setup(&request, parameters, QNetworkAccessManager::PutOperation);
	addContentTypeHeaders(&request);
	const QByteArray data = convertParameters(parameters);
	QNetworkReply* reply = networkAccessManager()->put(request, data);
	connect(reply, &QNetworkReply::finished, std::bind(&QAbstractOAuth::finished, this, reply));
	return reply;
}


QNetworkReply* QOAuth1::deleteResource(const QUrl& url, const QVariantMap& parameters)
{
	if (!networkAccessManager())
	{
		qCWarning(NetworkAuthLogging, "QNetworkAccessManager not available");
		return nullptr;
	}
	QNetworkRequest request(url);
	setup(&request, parameters, QNetworkAccessManager::DeleteOperation);
	QNetworkReply* reply = networkAccessManager()->deleteResource(request);
	connect(reply, &QNetworkReply::finished, [this, reply]()
	{
		emit finished(reply);
	});
	return reply;
}


QNetworkReply* QOAuth1::requestTemporaryCredentials(QNetworkAccessManager::Operation operation, const QUrl& url, const QVariantMap& parameters)
{
	_token.clear();
	_tokenSecret.clear();
	QVariantMap allParameters(parameters);
	allParameters.insert(Key::oauthCallback, callback());
	return requestToken(operation, url, qMakePair(_token, _tokenSecret), allParameters);
}


QNetworkReply* QOAuth1::requestTokenCredentials(QNetworkAccessManager::Operation operation, const QUrl& url, const QPair<QString, QString>& temporaryToken, const QVariantMap& parameters)
{
	_tokenRequested = true;
	return requestToken(operation, url, temporaryToken, parameters);
}


void QOAuth1::setup(QNetworkRequest* request, const QVariantMap& signingParameters, QNetworkAccessManager::Operation operation)
{
	auto oauthParams = createOAuthBaseParams();
	// Add signature parameter
	{
		QMultiMap<QString, QVariant> parameters(oauthParams);
		parameters.unite(QMultiMap<QString, QVariant>(signingParameters));
		const auto signature = generateSignature(parameters, request->url(), operation);
		oauthParams.insert(Key::oauthSignature, signature);
	}
	if (operation == QNetworkAccessManager::GetOperation)
	{
		if (signingParameters.size())
		{
			QUrl url = request->url();
			QUrlQuery query = QUrlQuery(url.query());
			for (auto it = signingParameters.begin(), end = signingParameters.end(); it != end; ++it)
			{
				query.addQueryItem(it.key(), it.value().toString());
			}
			url.setQuery(query);
			request->setUrl(url);
		}
	}
	request->setRawHeader("Authorization", generateAuthorizationHeader(oauthParams));
	if (operation == QNetworkAccessManager::PostOperation || operation == QNetworkAccessManager::PutOperation)
	{
		request->setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));
	}
}


void QOAuth1::setup(QNetworkRequest* request, const QVariantMap& signingParameters, const QByteArray& operationVerb)
{
	auto oauthParams = createOAuthBaseParams();
	// Add signature parameter
	{
		QMultiMap<QString, QVariant> parameters(oauthParams);
		parameters.unite(QMultiMap<QString, QVariant>(signingParameters));
		const auto signature = generateSignature(parameters, request->url(), operationVerb);
		oauthParams.insert(Key::oauthSignature, signature);
	}

	request->setRawHeader("Authorization", generateAuthorizationHeader(oauthParams));
}


QByteArray QOAuth1::nonce()
{
	return QAbstractOAuth::generateRandomString(8);
}


QByteArray QOAuth1::generateAuthorizationHeader(const QVariantMap& oauthParams)
{
	// TODO Add realm parameter support
	bool first = true;
	QString ret(QStringLiteral("OAuth "));
	QVariantMap headers(oauthParams);
	for (auto it = headers.begin(), end = headers.end(); it != end; ++it)
	{
		if (first)
		{
			first = false;
		}
		else
		{
			ret += QLatin1String(",");
		}
		ret += it.key() + QLatin1String("=\"") + QString::fromUtf8(QUrl::toPercentEncoding(it.value().toString())) + QLatin1Char('\"');
	}
	return ret.toUtf8();
}


void QOAuth1::grant()
{
	using Key = QOAuth1::OAuth1KeyString;

	if (_temporaryCredentialsUrl.isEmpty())
	{
		qCWarning(NetworkAuthLogging, "requestTokenUrl is empty");
		return;
	}
	if (_tokenCredentialsUrl.isEmpty())
	{
		qCWarning(NetworkAuthLogging, "authorizationGrantUrl is empty");
		return;
	}
	if (!_token.isEmpty() && status() == Status::Granted)
	{
		qCWarning(NetworkAuthLogging, "Already authenticated");
		return;
	}

	QMetaObject::Connection connection;
	connection = connect(this, &QAbstractOAuth::statusChanged, [&](Status status)
	{
		if (status == Status::TemporaryCredentialsReceived)
		{
			if (_authorizationUrl.isEmpty())
			{
				// try upgrading token without verifier
				auto reply = requestTokenCredentials(QNetworkAccessManager::PostOperation, _tokenCredentialsUrl, qMakePair(_token, _tokenSecret));
				connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater);
			}
			else
			{
				QMultiMap<QString, QVariant> parameters;
				parameters.insert(Key::oauthToken, _token);
				if (_modifyParametersFunction)
				{
					_modifyParametersFunction(Stage::RequestingAuthorization, &parameters);
				}
				// https://tools.ietf.org/html/rfc5849#section-2.2
				resourceOwnerAuthorization(_authorizationUrl, parameters);
			}
		}
		else if (status == Status::NotAuthenticated) {
			// Inherit class called QAbstractOAuth::setStatus(Status::NotAuthenticated);
			setTokenCredentials(QString(), QString());
			disconnect(connection);
		}
	});

	auto httpReplyHandler = qobject_cast<QOAuthHttpServerReplyHandler*>(replyHandler());
	if (httpReplyHandler)
	{
		connect(httpReplyHandler, &QOAuthHttpServerReplyHandler::callbackReceived, [&](const QVariantMap& values)
		{
			QString verifier = values.value(Key::oauthVerifier).toString();
			if (verifier.isEmpty())
			{
				qCWarning(NetworkAuthLogging, "%s not found in the callback", qPrintable(Key::oauthVerifier));
				return;
			}
			continueGrantWithVerifier(verifier);
		});
	}

	// requesting temporary credentials
	auto reply = requestTemporaryCredentials(QNetworkAccessManager::PostOperation, _temporaryCredentialsUrl);
	connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater);
}


void QOAuth1::continueGrantWithVerifier(const QString& verifier)
{
	QVariantMap parameters;
	parameters.insert(Key::oauthVerifier, verifier);
	auto reply = requestTokenCredentials(QNetworkAccessManager::PostOperation, _tokenCredentialsUrl, qMakePair(_token, _tokenSecret), parameters);
	connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater);
}

QT_END_NAMESPACE

