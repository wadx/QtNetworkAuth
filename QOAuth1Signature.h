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

#include <QtCore/qurl.h>
#include <QtCore/qvariant.h>
#include <QtCore/qshareddata.h>

QT_BEGIN_NAMESPACE

class QUrlQuery;


class QOAuth1Signature
{
public:
	enum class HttpRequestMethod {
		Head = 1,
		Get,
		Put,
		Post,
		Delete,
		Custom,

		Unknown = 0
	};

	explicit QOAuth1Signature(const QUrl& url = QUrl(), HttpRequestMethod method = HttpRequestMethod::Post, const QMultiMap<QString, QVariant>& parameters = {});
	QOAuth1Signature(const QUrl& url, const QString& clientSharedKey, const QString& tokenSecret, HttpRequestMethod method = HttpRequestMethod::Post, const QMultiMap<QString, QVariant>& parameters = {});
	QOAuth1Signature(const QOAuth1Signature& other);
	QOAuth1Signature(QOAuth1Signature&& other);
	~QOAuth1Signature();

	HttpRequestMethod httpRequestMethod() const;
	void setHttpRequestMethod(HttpRequestMethod method);

	QByteArray customMethodString() const;
	void setCustomMethodString(const QByteArray& verb);

	QUrl url() const;
	void setUrl(const QUrl& url);

	QMultiMap<QString, QVariant> parameters() const;
	void setParameters(const QMultiMap<QString, QVariant>& parameters);
	void addRequestBody(const QUrlQuery& body);

	void insert(const QString& key, const QVariant& value);
	QList<QString> keys() const;
	QVariant take(const QString& key);
	QVariant value(const QString& key, const QVariant& defaultValue = QVariant()) const;

	QString clientSharedKey() const;
	void setClientSharedKey(const QString& secret);

	QString tokenSecret() const;
	void setTokenSecret(const QString& secret);

	QByteArray hmacSha1() const;
	QByteArray rsaSha1() const;
	QByteArray plainText() const;

	static QByteArray plainText(const QString& clientSharedSecret, const QString& tokenSecret);

	void swap(QOAuth1Signature& other);
	QOAuth1Signature& operator=(const QOAuth1Signature& other);
	QOAuth1Signature& operator=(QOAuth1Signature&& other);

private:
	QByteArray signatureBaseString() const;
	QByteArray secret() const;
	static QByteArray parameterString(const QMultiMap<QString, QVariant>& parameters);
	static QByteArray encodeHeaders(const QMultiMap<QString, QVariant>& headers);


	QOAuth1Signature::HttpRequestMethod _method = QOAuth1Signature::HttpRequestMethod::Post;
	QByteArray                           _customVerb;
	QUrl                                 _url;
	QString                              _clientSharedKey;
	QString                              _tokenSecret;
	QMultiMap<QString, QVariant>         _parameters;

	static QOAuth1Signature             _shared_null;
};

QT_END_NAMESPACE

