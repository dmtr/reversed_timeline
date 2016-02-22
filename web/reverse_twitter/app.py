# coding: utf-8
import argparse
import asyncio
import configparser
import functools
import logging
import os
import signal
import sys
import time

import aiohttp_jinja2
import itsdangerous
import simplejson as json
import aiohttp
from aiohttp.web import Application, MsgType, WebSocketResponse, Response
from reverse_twitter.twtimeline import timeline


logger = logging.getLogger(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
COOKIE_MAX_AGE = 20
MAX_TWEETS = 5


def get_auth_cookie_name(app):
    return app['config']['http']['cookie_name']


def sign_client_key(client_key, secret_key):
    s = itsdangerous.URLSafeSerializer(secret_key)
    return s.dumps(client_key)


def unsign_client_key(key, secret_key):
    try:
        s = itsdangerous.URLSafeSerializer(secret_key)
        return s.loads(key)
    except Exception as e:
        logger.exception('Could not unsign %s', e)


def get_client_key(headers):
    return '{0}:{1}'.format(headers.get('X-Forwarded-For', '_'), time.time())


async def auth_middleware_factory(app, handler):
    async def middleware_handler(request):
        cookie_name = get_auth_cookie_name(app)
        if request.path == '/':
            if cookie_name not in request.cookies:
                resp = await handler(request)
                client_key = get_client_key(request.headers)
                resp.set_cookie(cookie_name, sign_client_key(client_key, app['secret_key']), max_age=COOKIE_MAX_AGE)
                app['clients'][client_key] = None
                return resp

        return await handler(request)
    return middleware_handler


async def get_tweets(resp, app, client_key, screen_name, count):
    tm = app['clients'][client_key]
    if tm is None or tm.screen_name != screen_name:
        timeline_options = timeline.TimelineOptions(count, 0, 0, True, screen_name)
    else:
        timeline_options = timeline.TimelineOptions(tm.count, tm.max_id, 0, tm.trim_user, tm.screen_name)

    get_timeline_func = functools.partial(
        timeline.get_timeline,
        consumer_key=app['tw_consumer_key'],
        consumer_secret=app['tw_consumer_secret'])

    tm = timeline.Timeline(timeline_options, get_timeline_func)
    app['clients'][client_key] = tm
    logger.debug('Timeline %s', tm)

    tweets = []
    try:
        async for t in tm:
            tweets.append(t)

        for t in reversed(tweets):
            resp.send_str(json.dumps({'type': 'tweet', 'tweet_id': t['id_str']}))
        resp.send_str(json.dumps({'type': 'end'}))
    except timeline.UserNotFound:
        resp.send_str(json.dumps({'type': 'notfound'}))
    except timeline.TwitterError:
        resp.send_str(json.dumps({'type': 'twitter_error'}))
    except Exception as e:
        logger.exception('Got error while requesting twitter api: %s', e)
        resp.send_str(json.dumps({'type': 'error'}))


async def ws_handler(request):
    resp = WebSocketResponse()
    ok, protocol = resp.can_start(request)
    logger.debug('ok %s, protocol %s', ok, protocol)
    if not ok:
        raise Exception('Could not start!')

    await resp.prepare(request)
    logger.debug('Someone joined.')
    app = request.app
    app['sockets'].append(resp)

    async for msg in resp:
        if msg.tp == MsgType.text:
            try:
                m = json.loads(msg.data)
                logger.debug('Got msg %s', m)
                if m['type'] == 'start':
                    client_key = unsign_client_key(m.get('client_key'), app['secret_key'])
                    if client_key and client_key in app['clients']:
                        await get_tweets(resp, app, client_key, m['screen_name'], m['count'])
                    else:
                        logger.info('Unknown client, closing')
                        await resp.close()
                        app['sockets'].remove(resp)
            except json.JSONDecodeError as e:
                logger.exception('Bad json %s', e)
                await resp.close()
                logger.debug('Connection is closed %s', resp)
                app['sockets'].remove(resp)

        elif msg.tp == MsgType.error:
            logger.exception('ws connection closed with exception %s', resp.exception())

    return resp


def index_handler(request):
    logger.debug('index_handler')
    response = aiohttp_jinja2.render_template('index.html', request, {})
    return response


async def create_app(loop, config, debug=False):
    app = Application(loop=loop, middlewares=[auth_middleware_factory])

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
    app['clients'] = {}
    app['config'] = config

    app.router.add_route('GET', '/', index_handler)
    app.router.add_route('GET', '/tweets', ws_handler)
    if debug:
        app.router.add_route('GET', '/static/{a}', static_handler)
        app.router.add_route('GET', '/static/{a}/{b}', static_handler)
        app.router.add_route('GET', '/static/{a}/{b}/{c}', static_handler)

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

    args = parser.parse_args()

    _format = '%(name)s:%(levelname)s %(module)s:%(lineno)d:%(asctime)s  %(message)s'
    logging.basicConfig(stream=sys.stdout, format=_format, level=getattr(logging, args.loglevel))

    config = configparser.ConfigParser()
    config.read(args.config)

    loop = asyncio.get_event_loop()
    if args.debug:
        loop.set_debug(True)

    loop.add_signal_handler(signal.SIGINT, lambda: loop.stop())
    app, srv, handler = loop.run_until_complete(create_app(loop, config, args.debug))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(cleanup(app, srv, handler))
