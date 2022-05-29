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

#include "QOAuthOobReplyHandler.h"
#include <QtNetwork/qhostaddress.h>
#include <QtNetwork/qtcpserver.h>
#include <QtNetwork/qnetworkaccessmanager.h>

QT_BEGIN_NAMESPACE

class QUrlQuery;


class QOAuthHttpServerReplyHandler : public QOAuthOobReplyHandler
{
	Q_OBJECT

public:
	explicit QOAuthHttpServerReplyHandler(QObject* parent = nullptr);
	explicit QOAuthHttpServerReplyHandler(quint16 port, QObject* parent = nullptr);
	explicit QOAuthHttpServerReplyHandler(const QHostAddress& address, quint16 port, QObject* parent = nullptr);
	~QOAuthHttpServerReplyHandler();

	QString callback() const override;

	QString callbackPath() const;
	void setCallbackPath(const QString& path);

	QString callbackText() const;
	void setCallbackText(const QString& text);

	quint16 port() const;

	bool listen(const QHostAddress& address = QHostAddress::Any, quint16 port = 0);
	void close();
	bool isListening() const;

private:
	void _q_clientConnected();
	void _q_readData(QTcpSocket* socket);
	void _q_answerClient(QTcpSocket* socket, const QUrl& url);

	struct QHttpRequest
	{
		bool readMethod(QTcpSocket* socket);
		bool readUrl(QTcpSocket* socket);
		bool readStatus(QTcpSocket* socket);
		bool readHeader(QTcpSocket* socket);
		enum class State
		{
			ReadingMethod,
			ReadingUrl,
			ReadingStatus,
			ReadingHeader,
			ReadingBody,
			AllDone
		};
		enum class Method
		{
			Unknown,
			Head,
			Get,
			Put,
			Post,
			Delete,
		};
		State                        _state = State::ReadingMethod;
		Method                       _method = Method::Unknown;
		quint16                      _port = 0;
		QByteArray                   _fragment;
		QUrl                         _url;
		QPair<quint8, quint8>        _version;
		QMap<QByteArray, QByteArray> _headers;
	};
private:
	QString                                         _text;
	QMap<QTcpSocket*, QSharedPointer<QHttpRequest>> _clients;
	QOAuthHttpServerReplyHandler*                   _q_ptr = nullptr;
	QTcpServer                                      _httpServer;
	QHostAddress                                    _listenAddress = QHostAddress::LocalHost;
	QString                                         _path;

};

QT_END_NAMESPACE

