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
#include "QAbstractOAuth2.h"
#include <QtCore/qurl.h>
#include <QtCore/qurlquery.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qmessageauthenticationcode.h>
#include <QtNetwork/qnetworkreply.h>
#include <QtNetwork/qnetworkrequest.h>
#include <QtNetwork/qnetworkaccessmanager.h>
#include <QtNetwork/qhttpmultipart.h>
#include "moc_QAbstractOAuth2.cpp"

QT_BEGIN_NAMESPACE

Q_DECLARE_LOGGING_CATEGORY(NetworkAuthLogging)

using Key = QAbstractOAuth2::OAuth2KeyString;
const QString Key::accessToken = QStringLiteral("access_token");
const QString Key::apiKey = QStringLiteral("api_key");
const QString Key::clientIdentifier = QStringLiteral("client_id");
const QString Key::clientSharedSecret = QStringLiteral("client_secret");
const QString Key::code = QStringLiteral("code");
const QString Key::error = QStringLiteral("error");
const QString Key::errorDescription = QStringLiteral("error_description");
const QString Key::errorUri = QStringLiteral("error_uri");
const QString Key::expiresIn = QStringLiteral("expires_in");
const QString Key::grantType = QStringLiteral("grant_type");
const QString Key::redirectUri = QStringLiteral("redirect_uri");
const QString Key::refreshToken = QStringLiteral("refresh_token");
const QString Key::responseType = QStringLiteral("response_type");
const QString Key::scope = QStringLiteral("scope");
const QString Key::state = QStringLiteral("state");
const QString Key::tokenType = QStringLiteral("token_type");


QAbstractOAuth2::QAbstractOAuth2(const QPair<QString, QString>& clientCredentials, const QUrl& authorizationUrl, QNetworkAccessManager* manager, QObject* parent)
	: QAbstractOAuth(authorizationUrl, clientCredentials.first, manager)
	, _clientIdentifierSharedKey(clientCredentials.second)
{}


QAbstractOAuth2::QAbstractOAuth2(QNetworkAccessManager* manager, QObject* parent)
	: QAbstractOAuth(manager, parent)
{}


QAbstractOAuth2::QAbstractOAuth2(QObject* parent)
	: QAbstractOAuth(nullptr, parent)
{}


QAbstractOAuth2::~QAbstractOAuth2()
{}


QString QAbstractOAuth2::generateRandomState()
{
	return QString::fromUtf8(generateRandomString(8));
}


QNetworkRequest QAbstractOAuth2::createRequest(QUrl url, const QVariantMap* parameters)
{
	QUrlQuery query(url.query());

	QNetworkRequest request;
	if (parameters)
	{
		for (auto it = parameters->begin(), end = parameters->end(); it != end; ++it)
		{
			query.addQueryItem(it.key(), it.value().toString());
		}
		url.setQuery(query);
	}
	else // POST, PUT request
	{
		addContentTypeHeaders(&request);
	}

	request.setUrl(url);
	request.setHeader(QNetworkRequest::UserAgentHeader, _userAgent);
	const QString bearer = _bearerFormat.arg(_token);
	request.setRawHeader("Authorization", bearer.toUtf8());
	return request;
}


void QAbstractOAuth2::prepareRequest(QNetworkRequest* request, const QByteArray& verb,
	const QByteArray& body)
{
	Q_UNUSED(verb);
	Q_UNUSED(body);
	request->setHeader(QNetworkRequest::UserAgentHeader, _userAgent);
	const QString bearer = _bearerFormat.arg(_token);
	request->setRawHeader("Authorization", bearer.toUtf8());
}


void QAbstractOAuth2::setResponseType(const QString& responseType)
{
	if (_responseType != responseType)
	{
		_responseType = responseType;
		Q_EMIT responseTypeChanged(responseType);
	}
}


QUrl QAbstractOAuth2::createAuthenticatedUrl(const QUrl& url, const QVariantMap& parameters)
{
	if (Q_UNLIKELY(_token.isEmpty()))
	{
		qCWarning(NetworkAuthLogging, "Empty access token");
		return QUrl();
	}
	QUrl ret = url;
	QUrlQuery query(ret.query());
	query.addQueryItem(Key::accessToken, _token);
	for (auto it = parameters.begin(), end = parameters.end(); it != end; ++it)
	{
		query.addQueryItem(it.key(), it.value().toString());
	}
	ret.setQuery(query);
	return ret;
}


QNetworkReply* QAbstractOAuth2::head(const QUrl& url, const QVariantMap& parameters)
{
	QNetworkReply* reply = networkAccessManager()->head(createRequest(url, &parameters));
	connect(reply, &QNetworkReply::finished, [this, reply]()
	{
		emit finished(reply);
	});
	return reply;
}


QNetworkReply* QAbstractOAuth2::get(const QUrl& url, const QVariantMap& parameters)
{
	QNetworkReply* reply = networkAccessManager()->get(createRequest(url, &parameters));
	connect(reply, &QNetworkReply::finished, [this, reply]()
	{
		emit finished(reply);
	});
	return reply;
}


QNetworkReply* QAbstractOAuth2::post(const QUrl& url, const QVariantMap& parameters)
{
	const auto data = convertParameters(parameters);
	return post(url, data);
}


QNetworkReply* QAbstractOAuth2::post(const QUrl& url, const QByteArray& data)
{
	QNetworkReply* reply = networkAccessManager()->post(createRequest(url), data);
	connect(reply, &QNetworkReply::finished, [this, reply]()
	{
		emit finished(reply);
	});
	return reply;
}


QNetworkReply* QAbstractOAuth2::post(const QUrl& url, QHttpMultiPart* multiPart)
{
	QNetworkReply* reply = networkAccessManager()->post(createRequest(url), multiPart);
	connect(reply, &QNetworkReply::finished, [this, reply]()
	{
		emit finished(reply);
	});
	return reply;
}


QNetworkReply* QAbstractOAuth2::put(const QUrl& url, const QVariantMap& parameters)
{
	const auto data = convertParameters(parameters);
	return put(url, data);
}


QNetworkReply* QAbstractOAuth2::put(const QUrl& url, const QByteArray& data)
{
	QNetworkReply* reply = networkAccessManager()->put(createRequest(url), data);
	connect(reply, &QNetworkReply::finished, std::bind(&QAbstractOAuth::finished, this, reply));
	return reply;
}


QNetworkReply* QAbstractOAuth2::put(const QUrl& url, QHttpMultiPart* multiPart)
{
	QNetworkReply* reply = networkAccessManager()->put(createRequest(url), multiPart);
	connect(reply, &QNetworkReply::finished, std::bind(&QAbstractOAuth::finished, this, reply));
	return reply;
}


QNetworkReply* QAbstractOAuth2::deleteResource(const QUrl& url, const QVariantMap& parameters)
{
	QNetworkReply* reply = networkAccessManager()->deleteResource(createRequest(url, &parameters));
	connect(reply, &QNetworkReply::finished, [this, reply]()
	{
		emit finished(reply);
	});
	return reply;
}


QString QAbstractOAuth2::scope() const
{
	return _scope;
}


void QAbstractOAuth2::setScope(const QString& scope)
{
	if (_scope != scope)
	{
		_scope = scope;
		Q_EMIT scopeChanged(scope);
	}
}


QString QAbstractOAuth2::userAgent() const
{
	return _userAgent;
}


void QAbstractOAuth2::setUserAgent(const QString& userAgent)
{
	if (_userAgent != userAgent)
	{
		_userAgent = userAgent;
		Q_EMIT userAgentChanged(userAgent);
	}
}


QString QAbstractOAuth2::responseType() const
{
	return _responseType;
}


QString QAbstractOAuth2::clientIdentifierSharedKey() const
{
	return _clientIdentifierSharedKey;
}


void QAbstractOAuth2::setClientIdentifierSharedKey(const QString& clientIdentifierSharedKey)
{
	if (_clientIdentifierSharedKey != clientIdentifierSharedKey)
	{
		_clientIdentifierSharedKey = clientIdentifierSharedKey;
		Q_EMIT clientIdentifierSharedKeyChanged(clientIdentifierSharedKey);
	}
}


QString QAbstractOAuth2::state() const
{
	return _state;
}


void QAbstractOAuth2::setState(const QString& state)
{
	if (state != _state)
	{
		_state = state;
		Q_EMIT stateChanged(state);
	}
}

QDateTime QAbstractOAuth2::expirationAt() const
{
	return _expiresAt;
}


QString QAbstractOAuth2::refreshToken() const
{
	return  _refreshToken;
}

void QAbstractOAuth2::setRefreshToken(const QString& refreshToken)
{
	if (_refreshToken != refreshToken)
	{
		_refreshToken = refreshToken;
		Q_EMIT refreshTokenChanged(refreshToken);
	}
}

QT_END_NAMESPACE

