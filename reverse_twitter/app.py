# coding: utf-8
import argparse
import asyncio
import configparser
import functools
import logging
import os
import sys

import aiohttp_jinja2
from aiohttp.web import Application, MsgType, WebSocketResponse
from reverse_twitter.twtimeline import timeline


logger = logging.getLogger(__name__)
BASE_DIR = os.path.dirname(__file__)


def _get_client_params():
    return (10, 0, 0, True)


async def get_tweets(app, resp, msg):
    screen_name = msg.data
    timeline_options = timeline.TimelineOptions(*_get_client_params(), screen_name)
    get_timeline_func = functools.partial(
        timeline.get_timeline,
        consumer_key=app['tw_consumer_key'],
        consumer_secret=app['tw_consumer_secret'])
    tm = timeline.Timeline(timeline_options, get_timeline_func)
    async for t in tm:
        resp.send_str(t['text'])


async def ws_handler(request):
    resp = WebSocketResponse()
    ok, protocol = resp.can_start(request)
    logger.debug('ok %s, protocol %s', ok, protocol)
    if not ok:
        raise Exception('Could not start!')

    await resp.prepare(request)
    logger.debug('Someone joined.')
    request.app['sockets'].append(resp)

    async for msg in resp:
        if msg.tp == MsgType.text:
            if msg.data == 'close':
                await resp.close()
                break
            else:
                await get_tweets(request.app, resp, msg)
        elif msg.tp == MsgType.error:
            logger.exception('ws connection closed with exception %s', resp.exception())

    logger.debug('Connection is closed %s', resp)
    request.app['sockets'].remove(resp)

    return resp


@aiohttp_jinja2.template('index.html')
def index_handler(request):
    return {}


async def create_app(loop, config):
    app = Application(loop=loop)
    aiohttp_jinja2.setup(
        app,
        loader=aiohttp_jinja2.jinja2.FileSystemLoader(os.path.join(BASE_DIR, 'templates'))
    )

    app['sockets'] = []
    app['tw_consumer_key'] = os.environ.get('CONSUMER_KEY')
    app['tw_consumer_secret'] = os.environ.get('CONSUMER_SECRET')
    app.router.add_route('GET', '/', index_handler)
    app.router.add_route('GET', '/tweets', ws_handler)

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--loglevel", action="store", dest="loglevel", default='DEBUG', choices=['DEBUG', 'INFO', 'WARNINGS', 'ERROR'], help="Log level")

    parser.add_argument("--config", action="store", dest="config", help="Path to config")

    args = parser.parse_args()

    _format = '%(name)s:%(levelname)s %(module)s:%(lineno)d:%(asctime)s  %(message)s'
    logging.basicConfig(stream=sys.stdout, format=_format, level=getattr(logging, args.loglevel))

    config = configparser.ConfigParser()
    config.read(args.config)

    loop = asyncio.get_event_loop()
    app, srv, handler = loop.run_until_complete(create_app(loop, config))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(cleanup(app, srv, handler))
