import asyncio
import configparser
import os
import pytest

from collections import deque
from operator import methodcaller
from unittest import mock
from aiohttp.streams import AsyncStreamReaderMixin
from aiohttp.protocol import RawRequestMessage
from aiohttp.multidict import CIMultiDict
from reverse_twitter.app import create_app, BASE_DIR


LIMIT = 2 ** 16
EOF_MARKER = b''

encode = methodcaller('encode', 'utf8')


class FakeStreamReader(AsyncStreamReaderMixin):

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


def prepare_request(path, method='GET', version='1.1', should_close=False, compression=None, **headers):
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
    handler = app.make_handler()()
    handler.transport = mock.Mock()
    resp = await handler.handle_request(req, FakeStreamReader())
    assert resp.code == 200
