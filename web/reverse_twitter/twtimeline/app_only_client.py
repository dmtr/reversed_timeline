# coding: utf-8
import argparse
import asyncio
import logging
import sys

from urllib.parse import urljoin

import aiohttp

API_URL = 'https://api.twitter.com/'
API_VER = '1.1/'
TIMEOUT = 10

logger = logging.getLogger(__name__)

_bearer_auth = None


class AuthError(Exception):
    pass


async def _get_bearer_token(consumer_key,  secret):
    data = {'grant_type': 'client_credentials'}
    with aiohttp.Timeout(TIMEOUT):
        async with aiohttp.post(urljoin(API_URL, 'oauth2/token'), data=data, auth=aiohttp.BasicAuth(consumer_key, secret)) as r:
            if r.status == 200:
                j = await r.json()
                if j.get('token_type') == 'bearer':
                    return j.get('access_token')
            else:
                logger.error('Got status %s', r.status)
                raise AuthError()


async def get_bearer_auth(consumer_key, consumer_secret):
    global _bearer_auth
    if _bearer_auth is None:
        bearer = await _get_bearer_token(consumer_key, consumer_secret)
        _bearer_auth = TwitterBearerAuth(bearer)
    return _bearer_auth


async def request(method, url, params=None, data=None, auth=None):
    url = urljoin(urljoin(API_URL, API_VER), url)
    logger.debug('Requesting url %s', url)
    with aiohttp.Timeout(TIMEOUT):
        async with aiohttp.request(method, url, params=params, data=data, auth=auth) as r:
            return (await r.json(), r)


async def get_timeline(url, consumer_key, consumer_secret):
    auth = await get_bearer_auth(consumer_key, consumer_secret)
    timeline = await request('GET', url, auth=auth)
    return timeline


class TwitterBearerAuth(aiohttp.BasicAuth):

    def __new__(cls, bearer):
        return super().__new__(cls, bearer)

    def __init__(self, bearer):
        self._bearer = bearer

    def encode(self):
        return 'Bearer ' + self._bearer


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    tw_group = parser.add_argument_group('Twitter options')

    tw_group.add_argument("--consumer-key", action="store", dest="consumer_key", required=True, help=u"Twitter consumer Key")

    tw_group.add_argument("--consumer-secret", action="store", dest="consumer_secret", required=True, help=u"Twitter consumer secret")

    parser.add_argument("--loglevel", action="store", dest="loglevel", default='DEBUG', choices=['DEBUG', 'INFO', 'WARNINGS', 'ERROR'], help=u"Log level")

    args = parser.parse_args()

    _format = '%(name)s:%(levelname)s %(module)s:%(lineno)d:%(asctime)s  %(message)s'
    logging.basicConfig(stream=sys.stdout, format=_format, level=getattr(logging, args.loglevel))

    loop = asyncio.get_event_loop()
    bearer = loop.run_until_complete(
       get_bearer_token(args.consumer_key, args.consumer_secret)
       )
    logger.info('Got %s', bearer)
    loop.close()
