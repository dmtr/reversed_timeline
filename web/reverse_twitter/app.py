# coding: utf-8
import argparse
import asyncio
import configparser
import functools
import logging
import os
import signal
import sys

import aiohttp
import aiohttp_jinja2
import itsdangerous
import rethinkdb as rdb
import simplejson as json
from urllib import parse

from aioauth_client import TwitterClient
from aiohttp.web import Application, MsgType, WebSocketResponse, Response
from reverse_twitter.twtimeline import timeline
from reverse_twitter.db import db


logger = logging.getLogger(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SESSION_COOKIE_MAX_AGE = 60 * 60 * 24


def get_session_cookie_name(app):
    return app['config']['http']['session_cookie']


def get_signed_cookie(secret_key, **kwargs):
    s = itsdangerous.URLSafeSerializer(secret_key)
    return s.dumps(kwargs)


def unsign_cookie(cookie, secret_key):
    try:
        s = itsdangerous.URLSafeSerializer(secret_key)
        return s.loads(cookie)
    except Exception as e:
        logger.exception('Could not unsign %s', e)


def start_session(ip, conn):
    res = rdb.table('session').insert({
        'ip': ip,
        'timestamp': rdb.now(),
        'valid': True,
        'twitter_auth': False
    }).run(conn)
    return res['generated_keys'][0]


def get_session_cookie(secret_key, headers, conn):
    return get_signed_cookie(secret_key, id=start_session(headers.get('X-Forwarded-For', None), conn))


def get_and_check_session(request, secret_key, domain, cookie_name):
    if 'SEC-WEBSOCKET-KEY' in request.headers:
        origin = parse.urlparse(request.headers.get('ORIGIN'))
        if origin.netloc != app['domain']:
            logger.debug('Wrong origin %s', origin)
            return

    s = unsign_cookie(request.cookies.get(cookie_name), secret_key)
    if s:
        s = rdb.table('session').get(s.get('id')).run(request.conn)
        if s and s['valid'] == True:
            return s


async def session_middleware_factory(app, handler):
    async def middleware_handler(request):
        logger.debug('headers %s, path %s, scheme %s', request.headers, request.path, request.scheme)
        cookie_name = get_session_cookie_name(app)
        if request.path == '/':
            if cookie_name not in request.cookies:
                resp = await handler(request)
                resp.set_cookie(cookie_name, get_session_cookie(app['secret_key'], request.headers, request.conn), max_age=SESSION_COOKIE_MAX_AGE)
                return resp

        request.session = get_and_check_session(request, app['secret_key'], app['domain'], cookie_name)

        return await handler(request)
    return middleware_handler


async def db_factory(app, handler):
    async def middleware_handler(request):
        conn = db.get_connection(app['config'])
        logger.debug('DB Connection is opened')
        if not conn:
            raise aiohttp.HttpProcessingError(code=500)
        request.conn = conn
        resp = await handler(request)
        conn.close()
        logger.debug('DB Connection is closed')
        return resp

    return middleware_handler


async def get_tweets(resp, app, session, screen_name, count, conn):
    t = rdb.table('session').get(session.get('id')).pluck('timeline').run(conn)
    logger.debug('got timeline from db %s', t)
    if not t or t['timeline'].get('screen_name') != screen_name:
        timeline_options = timeline.TimelineOptions(count, 0, 0, True, screen_name)
    else:
        t = t['timeline']
        timeline_options = timeline.TimelineOptions(t['count'], int(t['max_id']), 0, t['trim_user'], t['screen_name'])

    get_timeline_func = functools.partial(
        timeline.get_timeline,
        consumer_key=app['tw_consumer_key'],
        consumer_secret=app['tw_consumer_secret'])

    tm = timeline.Timeline(timeline_options, get_timeline_func)
    logger.debug('Timeline %s', tm)

    tweets = []
    try:
        async for t in tm:
            tweets.append(t)

        for t in reversed(tweets):
            resp.send_str(json.dumps({'type': 'tweet', 'tweet_id': t['id_str']}))
        resp.send_str(json.dumps({'type': 'end'}))
        rdb.table('session').get(session['id']).update({
            'timeline': {
                'max_id': str(tm.max_id),
                'since_id': str(tm.since_id),
                'screen_name': tm.screen_name,
                'trim_user': tm.trim_user,
                'count': tm.count
            }
        }).run(conn)
    except timeline.UserNotFound:
        resp.send_str(json.dumps({'type': 'error', 'desc': 'User not found'}))
    except timeline.TwitterError:
        resp.send_str(json.dumps({'type': 'error', 'desc': 'Error returned by Twitter'}))
    except Exception as e:
        logger.exception('Got error while requesting twitter api: %s', e)
        resp.send_str(json.dumps({'type': 'error', 'desc': 'Server error'}))


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
                    if request.session:
                        await get_tweets(resp, app, request.session, m['screen_name'], m['count'], request.conn)
                    else:
                        logger.info('Unknown client, closing')
                        await resp.close()
                        app['sockets'].remove(resp)
                        break
            except Exception as e:
                logger.exception('Got error %s', e)
                resp.send_str(json.dumps({'type': 'error', 'desc': 'Server error'}))
                await resp.close()
                logger.debug('Connection is closed %s', resp)
                app['sockets'].remove(resp)
                break

        elif msg.tp == MsgType.error:
            logger.exception('ws connection closed with exception %s', resp.exception())

    logger.debug('Return Response')
    return resp


async def create_app(loop, config, debug=False):
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
    app['domain'] = os.environ.get('DOMAIN')
    app['config'] = config

    app.router.add_route('GET', '/', index_handler)
    app.router.add_route('GET', '/signin', signin_handler)
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
    app, srv, handler = loop.run_until_complete(create_app(loop, config, args.debug))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(cleanup(app, srv, handler))
