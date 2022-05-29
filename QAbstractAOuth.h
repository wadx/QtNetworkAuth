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
#include <QtCore/qobject.h>
#include <QtCore/qstring.h>
#include <QtCore/qvariant.h>
#include <functional>
#include <QtNetwork/qtnetwork-config.h>
#include "QOAuthOobReplyHandler.h"

QT_BEGIN_NAMESPACE

class QString;
class QByteArray;
class QNetworkReply;
class QNetworkRequest;
class QNetworkAccessManager;
class QAbstractOAuthReplyHandler;


class QAbstractOAuth : public QObject
{
	Q_OBJECT
	Q_DISABLE_COPY(QAbstractOAuth)

	Q_ENUMS(Status)
	Q_ENUMS(Stage)
	Q_ENUMS(Error)
	Q_PROPERTY(QString clientIdentifier READ clientIdentifier WRITE setClientIdentifier NOTIFY clientIdentifierChanged)
	Q_PROPERTY(QString token READ token WRITE setToken NOTIFY tokenChanged)
	Q_PROPERTY(Status status  READ status NOTIFY statusChanged)
	Q_PROPERTY(QVariantMap extraTokens READ extraTokens NOTIFY extraTokensChanged)
	Q_PROPERTY(QUrl authorizationUrl READ authorizationUrl WRITE setAuthorizationUrl NOTIFY authorizationUrlChanged)
	Q_PROPERTY(QAbstractOAuth::ContentType contentType READ contentType WRITE setContentType NOTIFY contentTypeChanged)

public:
	enum class Status {
		NotAuthenticated,
		TemporaryCredentialsReceived,
		Granted,
		RefreshingToken
	};

	enum class Stage {
		RequestingTemporaryCredentials,
		RequestingAuthorization,
		RequestingAccessToken,
		RefreshingAccessToken
	};

	enum class Error {
		NoError,
		NetworkError,
		ServerError,

		OAuthTokenNotFoundError,
		OAuthTokenSecretNotFoundError,
		OAuthCallbackNotVerified,

		OAuthRefreshTokenExpired
	};

	enum class ContentType {
		WwwFormUrlEncoded,
		Json
	};

	typedef std::function<void(Stage, QMultiMap<QString, QVariant>*)> ModifyParametersFunction;

	QAbstractOAuth(const QUrl& authorizationUrl, const QString& clientIdentifier, QNetworkAccessManager* manager, QObject* parent = nullptr);
	explicit QAbstractOAuth(QNetworkAccessManager* manager, QObject* parent = nullptr);
	virtual ~QAbstractOAuth();

	QString clientIdentifier() const;
	void setClientIdentifier(const QString& clientIdentifier);
	QString token() const;
	void setToken(const QString& token);
	QNetworkAccessManager* networkAccessManager() const;
	void setNetworkAccessManager(QNetworkAccessManager* networkAccessManager);
	Status status() const;
	QUrl authorizationUrl() const;
	void setAuthorizationUrl(const QUrl& url);
	QVariantMap extraTokens() const;
	QAbstractOAuthReplyHandler* replyHandler() const;
	void setReplyHandler(QAbstractOAuthReplyHandler* handler);

	Q_INVOKABLE virtual QNetworkReply* head(const QUrl& url, const QVariantMap& parameters = QVariantMap()) = 0;
	Q_INVOKABLE virtual QNetworkReply* get(const QUrl& url, const QVariantMap& parameters = QVariantMap()) = 0;
	Q_INVOKABLE virtual QNetworkReply* post(const QUrl& url, const QVariantMap& parameters = QVariantMap()) = 0;
	Q_INVOKABLE virtual QNetworkReply* put(const QUrl& url, const QVariantMap& parameters = QVariantMap()) = 0;
	Q_INVOKABLE virtual QNetworkReply* deleteResource(const QUrl& url, const QVariantMap& parameters = QVariantMap()) = 0;

	virtual void prepareRequest(QNetworkRequest* request, const QByteArray& verb, const QByteArray& body = QByteArray()) = 0;
	ModifyParametersFunction modifyParametersFunction() const;
	void setModifyParametersFunction(const ModifyParametersFunction& modifyParametersFunction);
	ContentType contentType() const;
	void setContentType(ContentType contentType);

public Q_SLOTS:
	virtual void grant() = 0;

Q_SIGNALS:
	void clientIdentifierChanged(const QString& clientIdentifier);
	void tokenChanged(const QString& token);
	void statusChanged(Status status);
	void authorizationUrlChanged(const QUrl& url);
	void extraTokensChanged(const QVariantMap& tokens);
	void contentTypeChanged(ContentType contentType);
	void requestFailed(const Error error);
	void authorizeWithBrowser(const QUrl& url);
	void granted();
	void finished(QNetworkReply* reply);
	void replyDataReceived(const QByteArray& data);

protected:
	void setStatus(Status status);

	QString callback() const;

public:
	virtual void resourceOwnerAuthorization(const QUrl& url, const QMultiMap<QString, QVariant>& parameters);
	static QByteArray generateRandomString(quint8 length);
	QNetworkAccessManager* networkAccessManager();
	QByteArray convertParameters(const QVariantMap& parameters);
	void addContentTypeHeaders(QNetworkRequest* request);
	static QUrlQuery createQuery(const QMultiMap<QString, QVariant>& parameters);

protected:
	QString                                   _clientIdentifier;
	QString                                   _token;
	QUrl                                      _authorizationUrl;
	QVariantMap                               _extraTokens;
	QAbstractOAuth::Status                   _status = QAbstractOAuth::Status::NotAuthenticated;
	QNetworkAccessManager::Operation          _operation = QNetworkAccessManager::Operation::UnknownOperation;
	QPointer<QAbstractOAuthReplyHandler>     _replyHandler;
	QScopedPointer<QOAuthOobReplyHandler>    _defaultReplyHandler = QScopedPointer<QOAuthOobReplyHandler>(new QOAuthOobReplyHandler());
	QPointer<QNetworkAccessManager>           _networkAccessManagerPointer;
	QAbstractOAuth::ModifyParametersFunction _modifyParametersFunction;
	QAbstractOAuth::ContentType              _contentType = QAbstractOAuth::ContentType::WwwFormUrlEncoded;
};

QT_END_NAMESPACE

