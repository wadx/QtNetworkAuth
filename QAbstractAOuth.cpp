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
#include "QAbstractAOuth.h"
#include "QAbstractOAuthReplyHandler.h"
#include <QtCore/qurl.h>
#include <QtCore/qpair.h>
#include <QtCore/qstring.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qurlquery.h>
#include <QtCore/qjsondocument.h>
#include <QtCore/qmessageauthenticationcode.h>
#include <QtNetwork/qnetworkrequest.h>
#include <QtNetwork/qnetworkaccessmanager.h>
#include <QtNetwork/qnetworkreply.h>
#include <random>
#include "moc_QAbstractAOuth.cpp"

QT_BEGIN_NAMESPACE


QAbstractOAuth::QAbstractOAuth(const QUrl& authorizationUrl, const QString& clientIdentifier, QNetworkAccessManager* manager, QObject* parent)
	: QObject(parent)
	, _clientIdentifier(clientIdentifier)
	, _authorizationUrl(authorizationUrl)
	, _defaultReplyHandler(new QOAuthOobReplyHandler)
	, _networkAccessManagerPointer(manager)
{
	qRegisterMetaType<QAbstractOAuth::Error>();
}


QAbstractOAuth::QAbstractOAuth(QNetworkAccessManager* manager, QObject* parent)
	: QObject(parent)
	, _networkAccessManagerPointer(manager)
{
	qRegisterMetaType<QAbstractOAuth::Error>();
}


QAbstractOAuth::~QAbstractOAuth()
{}


QNetworkAccessManager* QAbstractOAuth::networkAccessManager()
{
	if (!_networkAccessManagerPointer)
	{
		_networkAccessManagerPointer = new QNetworkAccessManager(this);
	}
	return _networkAccessManagerPointer.data();
}


void QAbstractOAuth::setStatus(QAbstractOAuth::Status newStatus)
{
	if (_status != newStatus)
	{
		_status = newStatus;
		Q_EMIT statusChanged(_status);
		if (_status == QAbstractOAuth::Status::Granted)
		{
			Q_EMIT granted();
		}
	}
}


QByteArray QAbstractOAuth::generateRandomString(quint8 length)
{
	const char characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	static std::mt19937 randomEngine(QDateTime::currentDateTime().toMSecsSinceEpoch());
	std::uniform_int_distribution<int> distribution(0, sizeof(characters) - 2);
	QByteArray data;
	data.reserve(length);
	for (quint8 i = 0; i < length; ++i)
	{
		data.append(characters[distribution(randomEngine)]);
	}
	return data;
}


QByteArray QAbstractOAuth::convertParameters(const QVariantMap& parameters)
{
	QByteArray data;
	switch (_contentType)
	{
	case QAbstractOAuth::ContentType::Json:
		data = QJsonDocument::fromVariant(QVariant(parameters)).toJson();
		break;
	case QAbstractOAuth::ContentType::WwwFormUrlEncoded:
	{
		QUrlQuery query;
		for (auto it = parameters.begin(), end = parameters.end(); it != end; ++it)
		{
			query.addQueryItem(it.key(), it->toString());
		}
		data = query.toString(QUrl::FullyEncoded).toUtf8();
		break;
	}
	}
	return data;
}


void QAbstractOAuth::addContentTypeHeaders(QNetworkRequest* request)
{
	Q_ASSERT(request);

	switch (_contentType)
	{
	case QAbstractOAuth::ContentType::WwwFormUrlEncoded:
		request->setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));
		break;
	case QAbstractOAuth::ContentType::Json:
		request->setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
		break;
	}
}


QUrlQuery QAbstractOAuth::createQuery(const QMultiMap<QString, QVariant>& parameters)
{
	QUrlQuery query;
	for (auto it = parameters.begin(), end = parameters.end(); it != end; ++it)
	{
		query.addQueryItem(it.key(), it.value().toString());
	}
	return query;
}


QString QAbstractOAuth::clientIdentifier() const
{
	return _clientIdentifier;
}


void QAbstractOAuth::setClientIdentifier(const QString& clientIdentifier)
{
	if (_clientIdentifier != clientIdentifier)
	{
		_clientIdentifier = clientIdentifier;
		Q_EMIT clientIdentifierChanged(clientIdentifier);
	}
}


QString QAbstractOAuth::token() const
{
	return _token;
}


void QAbstractOAuth::setToken(const QString& token)
{
	if (_token != token)
	{
		_token = token;
		Q_EMIT tokenChanged(token);
	}
}


QNetworkAccessManager* QAbstractOAuth::networkAccessManager() const
{
	return _networkAccessManagerPointer.data();
}


void QAbstractOAuth::setNetworkAccessManager(QNetworkAccessManager* networkAccessManager)
{
	if (networkAccessManager != _networkAccessManagerPointer)
	{
		if (_networkAccessManagerPointer && _networkAccessManagerPointer->parent() == this)
		{
			delete _networkAccessManagerPointer.data();
		}
		_networkAccessManagerPointer = networkAccessManager;
	}
}


QAbstractOAuth::Status QAbstractOAuth::status() const
{
	return _status;
}


QUrl QAbstractOAuth::authorizationUrl() const
{
	return _authorizationUrl;
}


void QAbstractOAuth::setAuthorizationUrl(const QUrl& url)
{
	if (_authorizationUrl != url)
	{
		_authorizationUrl = url;
		Q_EMIT authorizationUrlChanged(url);
	}
}


QAbstractOAuthReplyHandler* QAbstractOAuth::replyHandler() const
{
	return _replyHandler ? _replyHandler.data() : _defaultReplyHandler.data();
}



void QAbstractOAuth::setReplyHandler(QAbstractOAuthReplyHandler* handler)
{
	_replyHandler = handler;
}


QAbstractOAuth::ModifyParametersFunction QAbstractOAuth::modifyParametersFunction() const
{
	return _modifyParametersFunction;
}


void QAbstractOAuth::setModifyParametersFunction(const QAbstractOAuth::ModifyParametersFunction& modifyParametersFunction)
{
	_modifyParametersFunction = modifyParametersFunction;
}


QAbstractOAuth::ContentType QAbstractOAuth::contentType() const
{
	return _contentType;
}


void QAbstractOAuth::setContentType(QAbstractOAuth::ContentType contentType)
{
	if (_contentType != contentType)
	{
		_contentType = contentType;
		Q_EMIT contentTypeChanged(contentType);
	}
}


QVariantMap QAbstractOAuth::extraTokens() const
{
	return _extraTokens;
}


QString QAbstractOAuth::callback() const
{
	return _replyHandler ? _replyHandler->callback()
		: _defaultReplyHandler->callback();
}


void QAbstractOAuth::resourceOwnerAuthorization(const QUrl& url, const QMultiMap<QString, QVariant>& parameters)
{
	QUrl u = url;
	u.setQuery(QAbstractOAuth::createQuery(parameters));
	Q_EMIT authorizeWithBrowser(u);
}

QT_END_NAMESPACE

