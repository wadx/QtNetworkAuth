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
#include "QOAuthHttpServerReplyHandler.h"
#include <QtCore/qurl.h>
#include <QtCore/qurlquery.h>
#include <QtCore/qcoreapplication.h>
#include <QtCore/qloggingcategory.h>
#include <QtNetwork/qtcpsocket.h>
#include <QtNetwork/qnetworkreply.h>
#include <cctype>
#include <cstring>
#include <functional>
#include "moc_qoauthhttpserverreplyhandler.cpp"

QT_BEGIN_NAMESPACE

Q_DECLARE_LOGGING_CATEGORY(NetworkAuthLogging)


QOAuthHttpServerReplyHandler::QOAuthHttpServerReplyHandler(QObject* parent)
	: QOAuthHttpServerReplyHandler(QHostAddress::Any, 0, parent)
{
}


QOAuthHttpServerReplyHandler::QOAuthHttpServerReplyHandler(quint16 port, QObject* parent)
	: QOAuthHttpServerReplyHandler(QHostAddress::Any, port, parent)
{
}


QOAuthHttpServerReplyHandler::QOAuthHttpServerReplyHandler(const QHostAddress& address, quint16 port, QObject* parent)
	: QOAuthOobReplyHandler(parent)
	, _listenAddress(address)
	, _text(QObject::tr("Callback received. Feel free to close this page."))
{
	QObject::connect(&_httpServer, &QTcpServer::newConnection, [this]()
	{
		_q_clientConnected();
	});
	listen(address, port);
}


QOAuthHttpServerReplyHandler::~QOAuthHttpServerReplyHandler()
{
	if (_httpServer.isListening())
	{
		_httpServer.close();
	}
}


QString QOAuthHttpServerReplyHandler::callback() const
{
	Q_ASSERT(_httpServer.isListening());
	const QUrl url(QString::fromLatin1("http://127.0.0.1:%1/%2").arg(_httpServer.serverPort()).arg(_path));
	return url.toString(QUrl::EncodeDelimiters);
}


QString QOAuthHttpServerReplyHandler::callbackPath() const
{
	return _path;
}


void QOAuthHttpServerReplyHandler::setCallbackPath(const QString& path)
{
	QString copy = path;
	while (copy.startsWith(QLatin1Char('/')))
	{
		copy = copy.mid(1);
	}
	_path = copy;
}


QString QOAuthHttpServerReplyHandler::callbackText() const
{
	return _text;
}


void QOAuthHttpServerReplyHandler::setCallbackText(const QString& text)
{
	_text = text;
}


quint16 QOAuthHttpServerReplyHandler::port() const
{
	return _httpServer.serverPort();
}


bool QOAuthHttpServerReplyHandler::listen(const QHostAddress& address, quint16 port)
{
	return _httpServer.listen(address, port);
}


void QOAuthHttpServerReplyHandler::close()
{
	return _httpServer.close();
}


bool QOAuthHttpServerReplyHandler::isListening() const
{
	return _httpServer.isListening();
}

void QOAuthHttpServerReplyHandler::_q_clientConnected()
{
	QTcpSocket* socket = _httpServer.nextPendingConnection();
	QObject::connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
	QObject::connect(socket, &QTcpSocket::readyRead, [this, socket]()
	{
		_q_readData(socket);
	});
}


void QOAuthHttpServerReplyHandler::_q_readData(QTcpSocket* socket)
{
	QSharedPointer<QHttpRequest> request;
	auto iter = _clients.find(socket);
	if (iter != _clients.end())
	{
		request = iter.value();
	}
	else
	{
		request = QSharedPointer<QHttpRequest>(new QHttpRequest());
		_clients.insert(socket, request);
	}
	request->_port = _httpServer.serverPort();
	bool error = false;
	if (Q_LIKELY(request->_state == QHttpRequest::State::ReadingMethod))
	{
		if (Q_UNLIKELY(error = !request->readMethod(socket)))
		{
			qCDebug(NetworkAuthLogging, "Invalid Method");
		}
	}
	if (Q_LIKELY(!error && request->_state == QHttpRequest::State::ReadingUrl))
	{
		if (Q_UNLIKELY(error = !request->readUrl(socket)))
		{
			qCDebug(NetworkAuthLogging, "Invalid URL");
		}
	}
	if (Q_LIKELY(!error && request->_state == QHttpRequest::State::ReadingStatus))
	{
		if (Q_UNLIKELY(error = !request->readStatus(socket)))
		{
			qCDebug(NetworkAuthLogging, "Invalid Status");
		}
	}
	if (Q_LIKELY(!error && request->_state == QHttpRequest::State::ReadingHeader))
	{
		if (Q_UNLIKELY(error = !request->readHeader(socket)))
		{
			qCDebug(NetworkAuthLogging, "Invalid Header");
		}
	}
	if (error)
	{
		socket->disconnectFromHost();
		_clients.remove(socket);
	}
	else if (!request->_url.isEmpty())
	{
		Q_ASSERT(request->_state != QHttpRequest::State::ReadingUrl);
		qCDebug(NetworkAuthLogging, "Received data, url=[%s]", qPrintable(request->_url.toString()));
		_q_answerClient(socket, request->_url);
		_clients.remove(socket);
	}
}


void QOAuthHttpServerReplyHandler::_q_answerClient(QTcpSocket* socket, const QUrl& url)
{
	if (url.path().endsWith("/favicon.ico"))
	{
		return; // its ok, browser asked for icon. fix by [wad] 04.05.2022
	}
	if (!url.path().startsWith(QLatin1String("/") + _path))
	{
		qCDebug(NetworkAuthLogging, "Invalid request: %s", qPrintable(url.toString()));
	}
	else
	{
		QVariantMap receivedData;
		const QUrlQuery query(url.query());
		const auto items = query.queryItems();
		for (auto it = items.begin(), end = items.end(); it != end; ++it)
		{
			receivedData.insert(it->first, it->second);
		}
		Q_EMIT callbackReceived(receivedData);
		const QByteArray html = QByteArrayLiteral("<html><head><title>") +
			qApp->applicationName().toUtf8() +
			QByteArrayLiteral("</title></head><body>") +
			_text.toUtf8() +
			QByteArrayLiteral("</body></html>");
		const QByteArray htmlSize = QByteArray::number(html.size());
		const QByteArray replyMessage = QByteArrayLiteral("HTTP/1.0 200 OK \r\n"
			"Content-Type: text/html; "
			"charset=\"utf-8\"\r\n"
			"Content-Length: ") + htmlSize +
			QByteArrayLiteral("\r\n\r\n") +
			html;
		socket->write(replyMessage);
	}
	socket->disconnectFromHost();
}


bool QOAuthHttpServerReplyHandler::QHttpRequest::readMethod(QTcpSocket* socket)
{
	bool finished = false;
	while (socket->bytesAvailable() && !finished)
	{
		char c;
		socket->getChar(&c);
		if (std::isupper(c) && _fragment.size() < 6) // here will be assert if no std::setlocale(LC_ALL, "en_US.UTF-8"); used before
		{
			_fragment += c;
		}
		else
		{
			finished = true;
		}
	}
	if (finished)
	{
		if (_fragment == "HEAD")
		{
			_method = Method::Head;
		}
		else if (_fragment == "GET")
		{
			_method = Method::Get;
		}
		else if (_fragment == "PUT")
		{
			_method = Method::Put;
		}
		else if (_fragment == "POST")
		{
			_method = Method::Post;
		}
		else if (_fragment == "DELETE")
		{
			_method = Method::Delete;
		}
		else
		{
			qCDebug(NetworkAuthLogging, "Invalid operation %s", _fragment.data());
		}
		_state = State::ReadingUrl;
		_fragment.clear();
		return _method != Method::Unknown;
	}
	return true;
}


bool QOAuthHttpServerReplyHandler::QHttpRequest::readUrl(QTcpSocket* socket)
{
	bool finished = false;
	while (socket->bytesAvailable() && !finished)
	{
		char c;
		socket->getChar(&c);
		if (std::isspace(c))
		{
			finished = true;
		}
		else
		{
			_fragment += c;
		}
	}
	if (finished)
	{
		if (!_fragment.startsWith("/"))
		{
			qCDebug(NetworkAuthLogging, "Invalid URL path %s", _fragment.constData());
			return false;
		}
		_url.setUrl(QStringLiteral("http://127.0.0.1:") + QString::number(_port) + QString::fromUtf8(_fragment));
		_state = State::ReadingStatus;
		if (!_url.isValid())
		{
			qCDebug(NetworkAuthLogging, "Invalid URL %s", _fragment.constData());
			return false;
		}
		_fragment.clear();
		return true;
	}
	return true;
}


bool QOAuthHttpServerReplyHandler::QHttpRequest::readStatus(QTcpSocket* socket)
{
	bool finished = false;
	while (socket->bytesAvailable() && !finished)
	{
		char c;
		socket->getChar(&c);
		_fragment += c;
		if (_fragment.endsWith("\r\n"))
		{
			finished = true;
			_fragment.resize(_fragment.size() - 2);
		}
	}
	if (finished)
	{
		if (!std::isdigit(_fragment.at(_fragment.size() - 3)) || !std::isdigit(_fragment.at(_fragment.size() - 1)))
		{
			qCDebug(NetworkAuthLogging, "Invalid version");
			return false;
		}
		_version = qMakePair(_fragment.at(_fragment.size() - 3) - '0', _fragment.at(_fragment.size() - 1) - '0');
		_state = State::ReadingHeader;
		_fragment.clear();
	}
	return true;
}


bool QOAuthHttpServerReplyHandler::QHttpRequest::readHeader(QTcpSocket* socket)
{
	while (socket->bytesAvailable())
	{
		char c;
		socket->getChar(&c);
		_fragment += c;
		if (_fragment.endsWith("\r\n"))
		{
			if (_fragment == "\r\n")
			{
				_state = State::ReadingBody;
				_fragment.clear();
				return true;
			}
			else
			{
				_fragment.chop(2);
				const int index = _fragment.indexOf(':');
				if (index == -1)
				{
					return false;
				}
				const QByteArray key = _fragment.mid(0, index).trimmed();
				const QByteArray value = _fragment.mid(index + 1).trimmed();
				_headers.insert(key, value);
				_fragment.clear();
			}
		}
	}
	return false;
}


QT_END_NAMESPACE


