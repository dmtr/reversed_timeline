# coding: utf-8
import argparse
import asyncio
import configparser
import logging
import os
import signal
import sys

import aiohttp
import aiohttp_jinja2

from aiohttp.web import Application, Response
from reverse_twitter.db import db
from reverse_twitter.middleware import db_factory, session_middleware_factory
from reverse_twitter.handlers import index_handler, ws_handler, signin_handler, callback_handler

logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def create_app(loop, config, debug=False):
    app = Application(loop=loop, middlewares=[db_factory, session_middleware_factory])

    @asyncio.coroutine
    def static_processor(request):
        return {'static_url': config['http']['static_url']}

    aiohttp_jinja2.setup(
        app,
        context_processors=[static_processor, aiohttp_jinja2.request_processor],
        loader=aiohttp_jinja2.jinja2.FileSystemLoader(os.path.join(BASE_DIR, 'templates'))
    )

    app['sockets'] = []
    app['tw_consumer_key'] = os.environ.get('CONSUMER_KEY')
    app['tw_consumer_secret'] = os.environ.get('CONSUMER_SECRET')
    app['secret_key'] = os.environ.get('SECRET_KEY')
    app['config'] = config

    app.router.add_route('GET', '/', index_handler)
    app.router.add_route('GET', '/signin', signin_handler)
    app.router.add_route('GET', '/callback', callback_handler)
    app.router.add_route('GET', '/tweets', ws_handler)
    if debug:
        app.router.add_route('GET', '/static/{a}', static_handler)
        app.router.add_route('GET', '/static/{a}/{b}', static_handler)
        app.router.add_route('GET', '/static/{a}/{b}/{c}', static_handler)
    return app


async def create_server(loop, config, debug):
    app = create_app(loop, config, debug)
    handler = app.make_handler()
    srv = await loop.create_server(handler, config['http']['host'], config['http'].getint('port'))
    logger.info("Server started")
    return app, srv, handler


async def cleanup(app, srv, handler):
    for ws in app['sockets']:
        ws.close()
    app['sockets'].clear()
    await asyncio.sleep(0.1)
    srv.close()
    await handler.finish_connections()
    await srv.wait_closed()
    logger.info('Done')


def static_handler(request):
    path = BASE_DIR + '/../' + request.path[1:]
    logger.info('Path %s', path)
    if os.path.isfile(path):
        with open(path, 'rb') as f:
            return Response(status=200, body=f.read())
    else:
        raise aiohttp.HttpProcessingError(code=404)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--loglevel", action="store", dest="loglevel", default='DEBUG', choices=['DEBUG', 'INFO', 'WARNINGS', 'ERROR'], help="Log level")

    parser.add_argument("--config", action="store", dest="config", help="Path to config")

    parser.add_argument("--debug", action="store_true", dest="debug", help="Set asyncio debug mode")

    parser.add_argument("--createdb", action="store_true", dest="createdb", help="Create DB and exit")

    args = parser.parse_args()

    _format = '%(name)s:%(levelname)s %(module)s:%(lineno)d:%(asctime)s  %(message)s'
    logging.basicConfig(stream=sys.stdout, format=_format, level=getattr(logging, args.loglevel))

    config = configparser.ConfigParser()
    config.read(args.config)

    if args.createdb:
        db.setup(config)
        sys.exit()

    loop = asyncio.get_event_loop()
    if args.debug:
        loop.set_debug(True)

    loop.add_signal_handler(signal.SIGINT, lambda: loop.stop())
    app, srv, handler = loop.run_until_complete(create_server(loop, config, args.debug))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(cleanup(app, srv, handler))
