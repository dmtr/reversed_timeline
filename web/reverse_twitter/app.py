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
from rethinkdb.errors import RqlRuntimeError, RqlDriverError, ReqlOpFailedError


logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

ANON_SESSION_COOKIE_MAX_AGE = 60 * 10
SESSION_COOKIE_MAX_AGE = 60 * 60 * 24 * 7

MSG_TYPES = ('get', 'get_newest', 'get_oldest')


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
        'logged': False
    }).run(conn)
    return res['generated_keys'][0]


def get_session_cookie(secret_key, headers, conn):
    return get_signed_cookie(secret_key, id=start_session(headers.get('X-Forwarded-For', None), conn))


def get_user_by_id(_id, conn):
    user = rdb.table('user').get_all(_id, index='current_session').coerce_to('array').run(conn)
    logger.debug('User %s', user)
    if user:
        return user[0]


def get_and_check_session(request, secret_key, domain, cookie_name):
    if 'SEC-WEBSOCKET-KEY' in request.headers:
        origin = parse.urlparse(request.headers.get('ORIGIN'))
        if origin.netloc != domain:
            logger.debug('Wrong origin %s', origin)
            return

    s = unsign_cookie(request.cookies.get(cookie_name), secret_key)
    if s:
        s = rdb.table('session').get(s.get('id')).run(request.conn)
        if s and s['valid'] == True:
            if s['logged']:
                user = get_user_by_id(s['id'], request.conn)
                if user:
                    s['user'] = user
                else:
                    logger.error('User not found by id %s', s['id'])
            return s


async def session_middleware_factory(app, handler):
    async def middleware_handler(request):
        logger.debug('headers %s, path %s, scheme %s', request.headers, request.path, request.scheme)
        cookie_name = get_session_cookie_name(app)
        if cookie_name in request.cookies:
            s = get_and_check_session(request, app['secret_key'], app['config']['http']['domain'], cookie_name)
            if s:
                request.session = s
                logger.debug('Session %s', request.session.get('id'))
                return await handler(request)

        resp = await handler(request)
        resp.set_cookie(cookie_name, get_session_cookie(app['secret_key'], request.headers, request.conn), max_age=ANON_SESSION_COOKIE_MAX_AGE)
        return resp

    return middleware_handler


def session_required(f):
    @functools.wraps(f)
    def wrapper(request):
        if not hasattr(request, 'session') or not request.session:
            return aiohttp.web.HTTPFound('/')
        return f(request)

    return wrapper


async def db_factory(app, handler):
    async def middleware_handler(request):
        conn = db.get_connection(app['config'])
        logger.debug('DB Connection is opened')
        if not conn:
            raise aiohttp.HttpProcessingError(code=500)
        request.conn = conn
        try:
            resp = await handler(request)
            return resp
        except (RqlRuntimeError, RqlDriverError, ReqlOpFailedError) as e:
            logger.exception('Db error %s', e)
            raise aiohttp.HttpProcessingError(code=500)
        except Exception as e:
            raise e
        finally:
            conn.close()
            logger.debug('DB Connection is closed')

    return middleware_handler


def get_twitter_client(app, session=None):
    client = TwitterClient(
        consumer_key=app['tw_consumer_key'],
        consumer_secret=app['tw_consumer_secret']
    )
    if session:
        client.oauth_token_secret = session['secret']
        client.oauth_token = session['token']
    return client


async def get_tweets_for_logged_user(url, app, session):
    client = get_twitter_client(app, session)
    u = parse.urlparse(url)
    params = dict(parse.parse_qsl(u.query))
    logger.debug('url %s, params %s', u.path, params)
    r = await client.request('GET', u.path, params=params)
    return (await r.json(), r)


def get_timeline_options(app, session, screen_name, count, what, conn):
    t = rdb.table('session').get(session.get('id')).pluck('timeline').run(conn)
    logger.debug('Got prev timeline %s', t)
    prev_timeline = None
    if not t or (screen_name and t['timeline'].get('screen_name') != screen_name):
        timeline_options = timeline.TimelineOptions(count, 0, 0, True, screen_name)
    else:
        t = t['timeline']
        prev_timeline = timeline.TimelineOptions(
            t['count'],
            int(t['max_id']),
            int(t['since_id']),
            t['trim_user'],
            t['screen_name']
        )

        timeline_options = timeline.TimelineOptions(
            prev_timeline.count,
            prev_timeline.max_id if what == 'get_oldest' else 0,
            prev_timeline.since_id if what == 'get_newest' else 0,
            prev_timeline.trim_user,
            prev_timeline.screen_name
        )
    return (timeline_options, prev_timeline)


def get_timeline(app, session, timeline_options, conn):
    url = timeline.USER_URL
    if session['logged']:
        get_timeline_func = functools.partial(
            get_tweets_for_logged_user,
            app=app,
            session=session
        )

        if 'user' not in session:
            user = get_user_by_id(session['id'], conn)
        else:
            user = session['user']
        if timeline_options.screen_name == user['username']:
            url = timeline.HOME_URL
    else:
        get_timeline_func = functools.partial(
            timeline.get_timeline,
            consumer_key=app['tw_consumer_key'],
            consumer_secret=app['tw_consumer_secret'])

    return timeline.Timeline(timeline_options, get_timeline_func, url=url)


async def get_tweets(resp, app, session, screen_name, count, what, conn):
    tm_options, prev_tm_options = get_timeline_options(app, session, screen_name, count, what, conn)
    tm = get_timeline(app, session, tm_options, conn)
    logger.debug('Timeline %s', tm)
    tweets = []
    try:
        async for t in tm:
            tweets.append(t)

        for t in reversed(tweets):
            resp.send_str(json.dumps({'type': 'tweet', 'tweet_id': t['id_str']}))
        resp.send_str(json.dumps({'type': 'end'}))

        def max_id():
            return str(tm.max_id) if prev_tm_options is None or (tm.max_id and tm.max_id < prev_tm_options.max_id) else str(prev_tm_options.max_id)

        def since_id():
            return str(tm.since_id) if prev_tm_options is None or tm.since_id > prev_tm_options.since_id else str(prev_tm_options.since_id)

        rdb.table('session').get(session['id']).update({
            'timeline': {
                'max_id': max_id(),
                'since_id': since_id(),
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


def index_handler(request):
    logger.debug('index_handler')
    context = {}
    cookie = None
    if hasattr(request, 'session') and request.session.get('logged'):
        if 'after_login' in request.GET:
            cookie = get_signed_cookie(app['secret_key'], id=request.session['id'])

        if 'user' in request.session:
            context['user'] = request.session['user']

    resp = aiohttp_jinja2.render_template('index.html', request, context)
    if cookie:
        cookie_name = get_session_cookie_name(request.app)
        resp.set_cookie(cookie_name, cookie,  max_age=SESSION_COOKIE_MAX_AGE)
    return resp


@session_required
async def signin_handler(request):
    client = get_twitter_client(request.app)
    client.params['oauth_callback'] = 'http://{0}/{1}'.format(request.host, 'callback')
    token, secret = await client.get_request_token()
    rdb.table('session').get(request.session['id']).update({
        'secret': secret,
        'token': token
    }).run(request.conn)

    return aiohttp.web.HTTPFound(client.get_authorize_url())


@session_required
async def callback_handler(request):
    client = get_twitter_client(request.app, request.session)
    oauth_token, oauth_token_secret = await client.get_access_token(request.GET)
    user, _ = await client.user_info()
    d = {}
    d.update(user.__dict__)
    session_id = request.session['id']
    d['current_session'] = session_id
    rdb.table('user').insert(d, conflict='update').run(request.conn)
    rdb.table('session').get(session_id).update({
        'secret': oauth_token_secret,
        'token': oauth_token,
        'logged': True
    }).run(request.conn)

    return aiohttp.web.HTTPFound('/?after_login')


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
                if m['type'] in MSG_TYPES:
                    if hasattr(request, 'session'):
                        await get_tweets(resp, app, request.session, m['screen_name'], m['count'], m['type'], request.conn)
                    else:
                        logger.info('Unknown client, closing')
                        break
            except Exception as e:
                logger.exception('Got error %s', e)
                resp.send_str(json.dumps({'type': 'error', 'desc': 'Server error'}))
                break

        elif msg.tp == MsgType.error:
            logger.exception('ws connection closed with exception %s', resp.exception())

    await resp.close()
    app['sockets'].remove(resp)
    logger.debug('Connection is closed %s', resp)
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
    app['config'] = config

    app.router.add_route('GET', '/', index_handler)
    app.router.add_route('GET', '/signin', signin_handler)
    app.router.add_route('GET', '/callback', callback_handler)
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
