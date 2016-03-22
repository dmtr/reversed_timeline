import asyncio
import configparser
import os
import pytest

import simplejson as json

from collections import deque
from operator import methodcaller
from unittest import mock
from aiohttp.streams import AsyncStreamReaderMixin
from aiohttp.protocol import HttpVersion
from aiohttp.protocol import RawRequestMessage
from aiohttp.multidict import CIMultiDict
from aiohttp.websocket import OPCODE_BINARY, OPCODE_TEXT, Message
from aiohttp.web import StreamResponse
from reverse_twitter.app import create_app, BASE_DIR


LIMIT = 2 ** 16
EOF_MARKER = b''
EOL_MARKER = object()

encode = methodcaller('encode', 'utf8')


class ResponseMock(mock.MagicMock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.buffer = []

    def write(self, chunk, *,
              drain=False, EOF_MARKER=EOF_MARKER, EOL_MARKER=EOL_MARKER):
        self.buffer.append(chunk)

    def parse_response(self):
        if not self.buffer:
            return None, None, None

        status, *headers = [(t[:t.find(b':')], t[t.find(b':') + 2:]) for t in self.buffer[0].splitlines() if t]
        headers = dict(headers)
        status = int(status[0].split(b' ')[1])
        body = self.buffer[1] if len(self.buffer) > 1 else None
        return status, headers, body


class StreamReaderMock(AsyncStreamReaderMixin):

    def __init__(self, *data):
        self._buffer = deque(data)
        self._buffer_size = len(data)
        self.total_bytes = len(data)
        self._buffer_offset = 0
        self._eof = self._buffer_size

    def exception(self):
        return None

    def set_exception(self, exc):
        pass

    def set_parser(self, p):
        return self

    def feed_eof(self):
        self._eof = True

    def is_eof(self):
        return self._eof

    def at_eof(self):
        return self._eof and not self._buffer

    @asyncio.coroutine
    def wait_eof(self):
        return

    def feed_data(self, data):
        assert not self._eof, 'feed_data after feed_eof'

        if not data:
            return

        self._buffer.append(data)
        self._buffer_size += len(data)
        self.total_bytes += len(data)

    @asyncio.coroutine
    def readline(self):
        line = []
        line_size = 0
        not_enough = True

        while not_enough:
            while self._buffer and not_enough:
                offset = self._buffer_offset
                ichar = self._buffer[0].find(b'\n', offset) + 1
                # Read from current offset to found b'\n' or to the end.
                data = self._read_nowait(ichar - offset if ichar else 0)
                line.append(data)
                line_size += len(data)
                if ichar:
                    not_enough = False

                if line_size > LIMIT:
                    raise ValueError('Line is too long')

            if self._eof:
                break
        return b''.join(line)

    @asyncio.coroutine
    def read(self, n=-1):
        if not n:
            return EOF_MARKER

        if n < 0:
            # This used to just loop creating a new waiter hoping to
            # collect everything in self._buffer, but that would
            # deadlock if the subprocess sends more than self.limit
            # bytes.  So just call self.readany() until EOF.
            blocks = []
            while True:
                block = yield from self.readany()
                if not block:
                    break
                blocks.append(block)
            return b''.join(blocks)

        return self._read_nowait(n)

    @asyncio.coroutine
    def readany(self):
        return self.read_nowait()

    @asyncio.coroutine
    def readexactly(self, n):
        return self.read_nowait(n)

    def read_nowait(self, n=None):
        if not self._buffer:
            return EOF_MARKER

        first_buffer = self._buffer[0]
        offset = self._buffer_offset
        if n and len(first_buffer) - offset > n:
            data = first_buffer[offset:offset + n]
            self._buffer_offset += n

        elif offset:
            self._buffer.popleft()
            data = first_buffer[offset:]
            self._buffer_offset = 0

        else:
            data = self._buffer.popleft()

        self._buffer_size -= len(data)
        return data


class WsResponseMock(StreamResponse):
    def __init__(self):
        super().__init__()
        self.out_buf = []
        self.close_called = False

    def __repr__(self):
        return 'WsResponseMock, out_buf items {0}'.format(len(self.out_buf))

    def set_data(self, data):
        self.in_buf = deque([make_msg([d]) for d in data])

    async def __aiter__(self):
        return self

    async def __anext__(self):
        if not self.in_buf:
            raise StopIteration
        m = self.in_buf.popleft()
        return m

    def can_start(self, r):
        return True, mock.MagicMock()

    async def prepare(self, r):
        return mock.MagicMock()

    def send_str(self, str):
        self.out_buf.append(str)

    async def close(self):
        self.close_called = True

    @asyncio.coroutine
    def write_eof(self):
        pass


def make_msg(data, binary=False):
    if binary:
        opcode = OPCODE_BINARY
    else:
        opcode = OPCODE_TEXT

    if opcode == OPCODE_TEXT:
        text = b''.join(data).decode('utf-8')
        return Message(OPCODE_TEXT, text, '')
    else:
        data = b''.join(data)
        return Message(OPCODE_BINARY, data, '')


def prepare_request(path, method='GET', version=HttpVersion(1, 1), should_close=False, compression=None, **headers):
    raw_headers = [(encode(k), encode(v)) for k, v in headers.items()]
    return RawRequestMessage(method, path, version, CIMultiDict(headers), raw_headers, should_close, compression)


@pytest.fixture
def config():
    config = configparser.ConfigParser()
    config.read(os.path.join(BASE_DIR, 'etc/config_test'))
    return config


@pytest.fixture
def app(event_loop, config):
    with mock.patch('reverse_twitter.app.os.environ', new={'SECRET_KEY': 'mysecret', 'CONSUMER_KEY': 'consumer_key', 'CONSUMER_SECRET': 'consumer_secret'}):
        return create_app(event_loop, config)


async def get_http_response(app, req, data=None):
    handler = app.make_handler()()
    handler.transport = mock.MagicMock()
    handler.reader = mock.MagicMock()
    handler.writer = ResponseMock()
    await handler.handle_request(req, StreamReaderMock() if data else StreamReaderMock(data))
    return handler.writer


async def get_websocket_response(app, path, data=None):
    headers = {
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'Sec-WebSocket-Protocol': 'chat, superchat',
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
        'Origin': 'http://{}'.format(app['config']['http']['domain'])
    }
    req = prepare_request(path, **headers)
    handler = app.make_handler()()
    handler.reader = mock.MagicMock()
    handler.writer = mock.MagicMock()
    handler.transport = mock.MagicMock()
    ws_mock = WsResponseMock()
    ws_mock.set_data(data)
    with mock.patch('reverse_twitter.handlers.WebSocketResponse', new=mock.MagicMock(return_value=ws_mock)):
        await handler.handle_request(req, StreamReaderMock())
        return ws_mock


def test_app_creation(app, config):
    assert app['secret_key'] == 'mysecret'
    assert app['tw_consumer_key'] == 'consumer_key'
    assert app['tw_consumer_secret'] == 'consumer_secret'
    assert config == app['config']
    assert app['config']['rdb']['dbname'] == 'rtimeline_test'
    assert app['sockets'] == []
    handler = app.make_handler()
    assert handler._app == app


@pytest.mark.asyncio
async def test_get_index(app):
    req = prepare_request('/')
    r = await get_http_response(app, req)
    assert r is not None
    status, headers, body = r.parse_response()
    assert status == 200
    assert b'SET-COOKIE' in headers
    assert body is not None


@pytest.mark.asyncio
async def test_get_tweets_wrong_msg(app):
    r = await get_websocket_response(app, '/tweets', [b'{"foo" : 1}'])
    assert r is not None
    assert r.close_called is True
    assert 1 == len(r.out_buf)
    m = json.loads(r.out_buf[0])
    assert m['type'] == 'error'
    assert len(app['sockets']) == 0


@pytest.mark.asyncio
async def test_get_tweets_no_session(app):
    r = await get_websocket_response(app, '/tweets', [b'{"type" : "get"}'])
    assert r is not None
    assert r.close_called is True
    assert 0 == len(r.out_buf)
    assert len(app['sockets']) == 0
