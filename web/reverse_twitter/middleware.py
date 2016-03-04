import functools
import logging

import itsdangerous
import aiohttp
import rethinkdb as rdb

from urllib import parse
from rethinkdb.errors import RqlRuntimeError, RqlDriverError, ReqlOpFailedError
from reverse_twitter.db import db


logger = logging.getLogger(__name__)

ANON_SESSION_COOKIE_MAX_AGE = 60 * 10


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
