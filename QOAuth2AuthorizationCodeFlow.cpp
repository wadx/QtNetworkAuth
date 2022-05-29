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
#include "QOAuth2AuthorizationCodeFlow.h"
#include "QOAuthHttpServerReplyHandler.h"
#include <QtCore/qmap.h>
#include <QtCore/qurl.h>
#include <QtCore/qvariant.h>
#include <QtCore/qurlquery.h>
#include <QtCore/qjsonobject.h>
#include <QtCore/qjsondocument.h>
#include <QtNetwork/qauthenticator.h>
#include <functional>
#include "moc_qoauth2authorizationcodeflow.cpp"

QT_BEGIN_NAMESPACE

Q_DECLARE_LOGGING_CATEGORY(NetworkAuthLogging)


QOAuth2AuthorizationCodeFlow::QOAuth2AuthorizationCodeFlow(const QUrl& authorizationUrl, const QUrl& accessTokenUrl, const QString& clientIdentifier, QNetworkAccessManager* manager, QObject* parent)
	: QAbstractOAuth2(qMakePair(clientIdentifier, QString()), authorizationUrl, manager)
	, _accessTokenUrl(accessTokenUrl)
{
	_responseType = QStringLiteral("code");
}


QOAuth2AuthorizationCodeFlow::QOAuth2AuthorizationCodeFlow(QObject* parent)
	: QOAuth2AuthorizationCodeFlow(nullptr, parent)
{}


QOAuth2AuthorizationCodeFlow::QOAuth2AuthorizationCodeFlow(QNetworkAccessManager* manager, QObject* parent)
	: QOAuth2AuthorizationCodeFlow(QString(), manager, parent)
{}


QOAuth2AuthorizationCodeFlow::QOAuth2AuthorizationCodeFlow(const QString& clientIdentifier, QNetworkAccessManager* manager, QObject* parent)
	: QOAuth2AuthorizationCodeFlow(QString(), QString(), clientIdentifier, manager, parent)
{}


QOAuth2AuthorizationCodeFlow::QOAuth2AuthorizationCodeFlow(const QUrl& authenticateUrl, const QUrl& accessTokenUrl, QNetworkAccessManager* manager, QObject* parent)
	: QOAuth2AuthorizationCodeFlow(authenticateUrl, accessTokenUrl, QString(), manager, parent)
{}


QOAuth2AuthorizationCodeFlow::~QOAuth2AuthorizationCodeFlow()
{}


void QOAuth2AuthorizationCodeFlow::_q_handleCallback(const QVariantMap& data)
{
	using Key = QAbstractOAuth2::OAuth2KeyString;

	if (_status != QAbstractOAuth::Status::NotAuthenticated)
	{
		qCDebug(NetworkAuthLogging, "Unexpected call");
		return;
	}

	Q_ASSERT(!_state.isEmpty());

	const QString error_ = data.value(Key::error).toString();
	const QString code = data.value(Key::code).toString();
	const QString receivedState = data.value(Key::state).toString();
	if (error_.size())
	{
		const QString uri = data.value(Key::errorUri).toString();
		const QString description = data.value(Key::errorDescription).toString();
		qCWarning(NetworkAuthLogging, "AuthenticationError: %s(%s): %s", qPrintable(error_), qPrintable(uri), qPrintable(description));
		Q_EMIT error(error_, description, uri);
		return;
	}
	if (code.isEmpty())
	{
		qCWarning(NetworkAuthLogging, "AuthenticationError: Code not received");
		return;
	}
	if (receivedState.isEmpty())
	{
		qCWarning(NetworkAuthLogging, "State not received");
		return;
	}
	if (_state != receivedState)
	{
		qCWarning(NetworkAuthLogging, "State mismatch");
		return;
	}

	setStatus(QAbstractOAuth::Status::TemporaryCredentialsReceived);

	QVariantMap copy(data);
	copy.remove(Key::code);
	_extraTokens = copy;
	requestAccessToken(code);
}


void QOAuth2AuthorizationCodeFlow::_q_accessTokenRequestFinished(const QVariantMap& values)
{
	using Key = QAbstractOAuth2::OAuth2KeyString;

	if (values.contains(Key::error))
	{
		const QString error = values.value(Key::error).toString();
		qCWarning(NetworkAuthLogging, "Error: %s", qPrintable(error));
		return;
	}

	bool ok;
	const QString accessToken = values.value(Key::accessToken).toString();
	_tokenType = values.value(Key::tokenType).toString();
	int expiresIn = values.value(Key::expiresIn).toInt(&ok);
	if (!ok)
	{
		expiresIn = -1;
	}
	if (values.value(Key::refreshToken).isValid())
	{
		setRefreshToken(values.value(Key::refreshToken).toString());
	}
	_scope = values.value(Key::scope).toString();
	if (accessToken.isEmpty())
	{
		qCWarning(NetworkAuthLogging, "Access token not received");
		return;
	}
	setToken(accessToken);

	const QDateTime currentDateTime = QDateTime::currentDateTime();
	if (expiresIn > 0 && currentDateTime.secsTo(_expiresAt) != expiresIn)
	{
		_expiresAt = currentDateTime.addSecs(expiresIn);
		Q_EMIT expirationAtChanged(_expiresAt);
	}

	QVariantMap copy(values);
	copy.remove(Key::accessToken);
	copy.remove(Key::expiresIn);
	copy.remove(Key::refreshToken);
	copy.remove(Key::scope);
	copy.remove(Key::tokenType);
	_extraTokens.insert(copy);
	setStatus(QAbstractOAuth::Status::Granted);
}


void QOAuth2AuthorizationCodeFlow::_q_authenticate(QNetworkReply* reply, QAuthenticator* authenticator)
{
	if (reply == _currentReply)
	{
		const auto url = reply->url();
		if (url == _accessTokenUrl)
		{
			authenticator->setUser(_clientIdentifier);
			authenticator->setPassword(QString());
		}
	}
}


QUrl QOAuth2AuthorizationCodeFlow::accessTokenUrl() const
{
	return _accessTokenUrl;
}


void QOAuth2AuthorizationCodeFlow::setAccessTokenUrl(const QUrl& accessTokenUrl)
{
	if (_accessTokenUrl != accessTokenUrl)
	{
		_accessTokenUrl = accessTokenUrl;
		Q_EMIT accessTokenUrlChanged(accessTokenUrl);
	}
}


void QOAuth2AuthorizationCodeFlow::grant()
{
	if (_authorizationUrl.isEmpty())
	{
		qCWarning(NetworkAuthLogging, "No authenticate Url set");
		return;
	}
	if (_accessTokenUrl.isEmpty())
	{
		qCWarning(NetworkAuthLogging, "No request access token Url set");
		return;
	}
	resourceOwnerAuthorization(_authorizationUrl);
}


void QOAuth2AuthorizationCodeFlow::refreshAccessToken()
{
	if (_refreshToken.isEmpty())
	{
		qCWarning(NetworkAuthLogging, "Cannot refresh access token. Empty refresh token");
		return;
	}
	if (_status == Status::RefreshingToken)
	{
		qCWarning(NetworkAuthLogging, "Cannot refresh access token. Refresh Access Token is already in progress");
		return;
	}

	using Key = QAbstractOAuth2::OAuth2KeyString;

	QMultiMap<QString, QVariant> parameters;
	QNetworkRequest request(_accessTokenUrl);
	QUrlQuery query;
	parameters.insert(Key::grantType, QStringLiteral("refresh_token"));
	parameters.insert(Key::refreshToken, _refreshToken);
	parameters.insert(Key::redirectUri, QUrl::toPercentEncoding(callback()));
	parameters.insert(Key::clientIdentifier, _clientIdentifier);
	parameters.insert(Key::clientSharedSecret, _clientIdentifierSharedKey);
	if (_modifyParametersFunction)
	{
		_modifyParametersFunction(Stage::RefreshingAccessToken, &parameters);
	}
	query = QAbstractOAuth::createQuery(parameters);
	request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));

	const QString data = query.toString(QUrl::FullyEncoded);
	_currentReply = networkAccessManager()->post(request, data.toUtf8());
	_status = Status::RefreshingToken;

	QNetworkReply* reply = _currentReply.data();
	QAbstractOAuthReplyHandler* handler = replyHandler();
	connect(reply, &QNetworkReply::finished, [handler, reply]()
	{
		handler->networkReplyFinished(reply);
	});
	connect(reply, &QNetworkReply::errorOccurred, [this, reply](QNetworkReply::NetworkError error)
	{
		qCInfo(NetworkAuthLogging, ) << "Network error:" << static_cast<int>(error) << " Error string:" << reply->errorString();
		if (reply->bytesAvailable() > 0)
		{
			qCInfo(NetworkAuthLogging, ) << qPrintable(reply->readAll());
		}
		Q_EMIT requestFailed(QAbstractOAuth::Error::OAuthRefreshTokenExpired);
	});
	connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater);
	connect(_replyHandler.data(), &QAbstractOAuthReplyHandler::tokensReceived, this, &QOAuth2AuthorizationCodeFlow::_q_accessTokenRequestFinished, Qt::UniqueConnection);
	connect(networkAccessManager(), &QNetworkAccessManager::authenticationRequired, this, &QOAuth2AuthorizationCodeFlow::_q_authenticate, Qt::UniqueConnection);
}


QUrl QOAuth2AuthorizationCodeFlow::buildAuthenticateUrl(const QMultiMap<QString, QVariant>& parameters)
{
	using Key = QAbstractOAuth2::OAuth2KeyString;

	if (_state.isEmpty())
	{
		setState(QAbstractOAuth2::generateRandomState());
	}
	Q_ASSERT(!_state.isEmpty());
	const QString state = _state;

	QMultiMap<QString, QVariant> p(parameters);
	QUrl url(_authorizationUrl);
	p.insert(Key::responseType, responseType());
	p.insert(Key::clientIdentifier, _clientIdentifier);
	p.insert(Key::redirectUri, callback());
	p.insert(Key::scope, _scope);
	p.insert(Key::state, state);
	if (_modifyParametersFunction)
	{
		_modifyParametersFunction(Stage::RequestingAuthorization, &p);
	}
	url.setQuery(createQuery(p));
	connect(_replyHandler.data(), &QAbstractOAuthReplyHandler::callbackReceived, this, &QOAuth2AuthorizationCodeFlow::authorizationCallbackReceived, Qt::UniqueConnection);
	setStatus(QAbstractOAuth::Status::NotAuthenticated);
	qCDebug(NetworkAuthLogging, "Generated URL: %s", qPrintable(url.toString()));
	return url;
}


void QOAuth2AuthorizationCodeFlow::requestAccessToken(const QString& code)
{
	using Key = QAbstractOAuth2::OAuth2KeyString;

	QMultiMap<QString, QVariant> parameters;
	QNetworkRequest request(_accessTokenUrl);
	QUrlQuery query;
	parameters.insert(Key::grantType, QStringLiteral("authorization_code"));
	parameters.insert(Key::code, QUrl::toPercentEncoding(code));
	parameters.insert(Key::redirectUri, QUrl::toPercentEncoding(callback()));
	parameters.insert(Key::clientIdentifier, QUrl::toPercentEncoding(_clientIdentifier));
	if (!_clientIdentifierSharedKey.isEmpty())
	{
		parameters.insert(Key::clientSharedSecret, _clientIdentifierSharedKey);
	}
	if (_modifyParametersFunction)
	{
		_modifyParametersFunction(Stage::RequestingAccessToken, &parameters);
	}
	query = QAbstractOAuth::createQuery(parameters);
	request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));

	const QString data = query.toString(QUrl::FullyEncoded);
	QNetworkReply* reply = networkAccessManager()->post(request, data.toUtf8());
	_currentReply = reply;
	QAbstractOAuthReplyHandler* handler = replyHandler();
	QObject::connect(reply, &QNetworkReply::finished, [handler, reply]
	{
		handler->networkReplyFinished(reply);
	});
	connect(_replyHandler.data(), &QAbstractOAuthReplyHandler::tokensReceived, this, &QOAuth2AuthorizationCodeFlow::_q_accessTokenRequestFinished, Qt::UniqueConnection);
	connect(networkAccessManager(), &QNetworkAccessManager::authenticationRequired, this, &QOAuth2AuthorizationCodeFlow::_q_authenticate, Qt::UniqueConnection);
}


void QOAuth2AuthorizationCodeFlow::resourceOwnerAuthorization(const QUrl& url, const QMultiMap<QString, QVariant>& parameters)
{
	if (Q_UNLIKELY(url != _authorizationUrl))
	{
		qCWarning(NetworkAuthLogging, "Invalid URL: %s", qPrintable(url.toString()));
		return;
	}
	const QUrl u = buildAuthenticateUrl(parameters);
	connect(this, &QOAuth2AuthorizationCodeFlow::authorizationCallbackReceived, this, &QOAuth2AuthorizationCodeFlow::_q_handleCallback, Qt::UniqueConnection);
	Q_EMIT authorizeWithBrowser(u);
}

QT_END_NAMESPACE


