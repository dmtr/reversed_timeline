import functools
import logging

import aiohttp
import aiohttp_jinja2
import rethinkdb as rdb
import simplejson as json

from urllib import parse
from aiohttp.web import MsgType, WebSocketResponse
from aioauth_client import TwitterClient
from reverse_twitter.middleware import session_required, get_user_by_id, get_signed_cookie, get_session_cookie_name
from reverse_twitter.twtimeline import timeline

logger = logging.getLogger(__name__)

SESSION_COOKIE_MAX_AGE = 60 * 60 * 24 * 7

MSG_TYPES = ('get', 'get_newest', 'get_oldest')


def index_handler(request):
    logger.debug('index_handler')
    context = {}
    cookie = None
    if hasattr(request, 'session') and request.session.get('logged'):
        if 'after_login' in request.GET:
            cookie = get_signed_cookie(request.app['secret_key'], id=request.session['id'])

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


def get_timeline_options(app, session, screen_name, count, what, home, conn):
    t = rdb.table('session').get(session.get('id')).pluck('timeline').run(conn)
    logger.debug('Got prev timeline %s', t)
    prev_timeline = None
    if not t or (screen_name and t['timeline'].get('screen_name') != screen_name) or (home != t['timeline'].get('home')):
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


def get_timeline(app, session, timeline_options, home, conn):
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
        if timeline_options.screen_name == user['username'] and home:
            url = timeline.HOME_URL
    else:
        get_timeline_func = functools.partial(
            timeline.get_timeline,
            consumer_key=app['tw_consumer_key'],
            consumer_secret=app['tw_consumer_secret'])

    return timeline.Timeline(timeline_options, get_timeline_func, url=url)


def from_dict(d, *args):
    res = []
    for a in args:
        res.append(d[a])
    return res


async def get_tweets(resp, app, session, msg, conn):
    screen_name, count, what, home = from_dict(msg, 'screen_name', 'count', 'type', 'home')
    tm_options, prev_tm_options = get_timeline_options(app, session, screen_name, count, what, home, conn)
    tm = get_timeline(app, session, tm_options, home, conn)
    logger.debug('%s', tm)
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
                'count': tm.count,
                'home': home
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
                if m['type'] in MSG_TYPES:
                    if hasattr(request, 'session'):
                        await get_tweets(resp, app, request.session, m, request.conn)
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
