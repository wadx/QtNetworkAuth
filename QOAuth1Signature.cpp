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
#include "QOAuth1Signature.h"
#include <QtCore/qurlquery.h>
#include <QtCore/qloggingcategory.h>
#include <QtCore/qmessageauthenticationcode.h>
#include <QtNetwork/qnetworkaccessmanager.h>
#include <functional>
#include <type_traits>

QT_BEGIN_NAMESPACE

Q_LOGGING_CATEGORY(loggingCategory, "qt.networkauth.oauth1.signature")

static_assert(static_cast<int>(QOAuth1Signature::HttpRequestMethod::Head) ==
	static_cast<int>(QNetworkAccessManager::HeadOperation) &&
	static_cast<int>(QOAuth1Signature::HttpRequestMethod::Get) ==
	static_cast<int>(QNetworkAccessManager::GetOperation) &&
	static_cast<int>(QOAuth1Signature::HttpRequestMethod::Put) ==
	static_cast<int>(QNetworkAccessManager::PutOperation) &&
	static_cast<int>(QOAuth1Signature::HttpRequestMethod::Post) ==
	static_cast<int>(QNetworkAccessManager::PostOperation) &&
	static_cast<int>(QOAuth1Signature::HttpRequestMethod::Delete) ==
	static_cast<int>(QNetworkAccessManager::DeleteOperation),
	"Invalid QOAuth1Signature::HttpRequestMethod enumeration values");

QOAuth1Signature QOAuth1Signature::_shared_null;


QOAuth1Signature::QOAuth1Signature(const QUrl& url, QOAuth1Signature::HttpRequestMethod method, const QMultiMap<QString, QVariant>& parameters)
	: _method(method), _url(url), _clientSharedKey(), _tokenSecret(), _parameters()
{}


QOAuth1Signature::QOAuth1Signature(const QUrl& url, const QString& clientSharedKey, const QString& tokenSecret, HttpRequestMethod method, const QMultiMap<QString, QVariant>& parameters)
	: _method(method), _url(url), _clientSharedKey(clientSharedKey), _tokenSecret(tokenSecret), _parameters(parameters)
{}


QOAuth1Signature::QOAuth1Signature(const QOAuth1Signature& other)
{}


QOAuth1Signature::QOAuth1Signature(QOAuth1Signature&& other)
{
}


QOAuth1Signature::~QOAuth1Signature()
{}


QByteArray QOAuth1Signature::signatureBaseString() const
{
	QByteArray base;
	switch (_method)
	{
	case QOAuth1Signature::HttpRequestMethod::Head:
		base.append("HEAD");
		break;
	case QOAuth1Signature::HttpRequestMethod::Get:
		base.append("GET");
		break;
	case QOAuth1Signature::HttpRequestMethod::Put:
		base.append("PUT");
		break;
	case QOAuth1Signature::HttpRequestMethod::Post:
		base.append("POST");
		break;
	case QOAuth1Signature::HttpRequestMethod::Delete:
		base.append("DELETE");
		break;
	case QOAuth1Signature::HttpRequestMethod::Custom:
		if (!_customVerb.isEmpty())
		{
			base.append(_customVerb);
		}
		else {
			qCCritical(loggingCategory, "QOAuth1Signature: HttpRequestMethod::Custom requires the verb to be set via setCustomMethodString");
		}
		break;
	default:
		qCCritical(loggingCategory, "QOAuth1Signature: HttpRequestMethod not supported");
	}
	base.append('&');
	base.append(QUrl::toPercentEncoding(_url.toString(QUrl::RemoveQuery)) + "&");

	QMultiMap<QString, QVariant> p = _parameters;
	{
		// replace '+' with spaces now before decoding so that '%2B' gets left as '+'
		const QString query = _url.query().replace(QLatin1Char('+'), QLatin1Char(' '));
		const auto queryItems = QUrlQuery(query).queryItems(QUrl::FullyDecoded);
		for (auto it = queryItems.begin(), end = queryItems.end(); it != end; ++it)
			p.insert(it->first, it->second);
	}
	base.append(encodeHeaders(p));
	return base;
}


QByteArray QOAuth1Signature::secret() const
{
	QByteArray secret;
	secret.append(QUrl::toPercentEncoding(_clientSharedKey));
	secret.append('&');
	secret.append(QUrl::toPercentEncoding(_tokenSecret));
	return secret;
}


QByteArray QOAuth1Signature::parameterString(const QMultiMap<QString, QVariant>& parameters)
{
	QByteArray ret;
	auto previous = parameters.end();
	for (auto it = parameters.begin(), end = parameters.end(); it != end; previous = it++)
	{
		if (previous != parameters.end())
		{
			if (Q_UNLIKELY(previous.key() == it.key()))
			{
				qCWarning(loggingCategory, "duplicated key %s", qPrintable(it.key()));
			}
			ret.append("&");
		}
		ret.append(QUrl::toPercentEncoding(it.key()));
		ret.append("=");
		ret.append(QUrl::toPercentEncoding(it.value().toString()));
	}
	return ret;
}


QByteArray QOAuth1Signature::encodeHeaders(const QMultiMap<QString, QVariant>& headers)
{
	return QUrl::toPercentEncoding(QString::fromLatin1(parameterString(headers)));
}


QOAuth1Signature::HttpRequestMethod QOAuth1Signature::httpRequestMethod() const
{
	return _method;
}

void QOAuth1Signature::setHttpRequestMethod(QOAuth1Signature::HttpRequestMethod method)
{
	_method = method;
}


QByteArray QOAuth1Signature::customMethodString() const
{
	return _customVerb;
}


void QOAuth1Signature::setCustomMethodString(const QByteArray& verb)
{
	_method = QOAuth1Signature::HttpRequestMethod::Custom;
	_customVerb = verb;
}


QUrl QOAuth1Signature::url() const
{
	return _url;
}


void QOAuth1Signature::setUrl(const QUrl& url)
{
	_url = url;
}


QMultiMap<QString, QVariant> QOAuth1Signature::parameters() const
{
	return _parameters;
}


void QOAuth1Signature::setParameters(const QMultiMap<QString, QVariant>& parameters)
{
	_parameters.clear();
	for (auto it = parameters.cbegin(), end = parameters.cend(); it != end; ++it)
	{
		_parameters.insert(it.key(), it.value());
	}
}


void QOAuth1Signature::addRequestBody(const QUrlQuery& body)
{
	const auto list = body.queryItems();
	for (auto it = list.begin(), end = list.end(); it != end; ++it)
	{
		_parameters.replace(it->first, it->second);
	}
}


void QOAuth1Signature::insert(const QString& key, const QVariant& value)
{
	_parameters.replace(key, value);
}


QList<QString> QOAuth1Signature::keys() const
{
	return _parameters.uniqueKeys();
}


QVariant QOAuth1Signature::take(const QString& key)
{
	return _parameters.take(key);
}


QVariant QOAuth1Signature::value(const QString& key, const QVariant& defaultValue) const
{
	return _parameters.value(key, defaultValue);
}


QString QOAuth1Signature::clientSharedKey() const
{
	return _clientSharedKey;
}


void QOAuth1Signature::setClientSharedKey(const QString& secret)
{
	_clientSharedKey = secret;
}


QString QOAuth1Signature::tokenSecret() const
{
	return _tokenSecret;
}


void QOAuth1Signature::setTokenSecret(const QString& secret)
{
	_tokenSecret = secret;
}


QByteArray QOAuth1Signature::hmacSha1() const
{
	QMessageAuthenticationCode code(QCryptographicHash::Sha1);
	code.setKey(secret());
	code.addData(signatureBaseString());
	return code.result();
}


QByteArray QOAuth1Signature::rsaSha1() const
{
	qCCritical(loggingCategory, "RSA-SHA1 signing method not supported");
	return QByteArray();
}


QByteArray QOAuth1Signature::plainText() const
{
	return plainText(_clientSharedKey, _tokenSecret);
}


QByteArray QOAuth1Signature::plainText(const QString& clientSharedKey, const QString& tokenSecret)
{
	QByteArray ret;
	ret += clientSharedKey.toUtf8() + '&' + tokenSecret.toUtf8();
	return ret;
}


void QOAuth1Signature::swap(QOAuth1Signature& other)
{
	qSwap(*this, other);
}


QOAuth1Signature& QOAuth1Signature::operator=(const QOAuth1Signature& other)
{
//	if (*this != other)
//	{
		QOAuth1Signature tmp(other);
		tmp.swap(*this);
//	}
	return *this;
}


QOAuth1Signature& QOAuth1Signature::operator=(QOAuth1Signature&& other)
{
	QOAuth1Signature moved(std::move(other));
	swap(moved);
	return *this;
}

QT_END_NAMESPACE
