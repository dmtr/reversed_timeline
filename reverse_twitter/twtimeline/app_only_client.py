# coding: utf-8
import argparse
import asyncio
import base64
import logging
import sys

from operator import methodcaller
from urllib.parse import quote
from urllib.parse import urljoin

import aiohttp

API_URL = 'https://api.twitter.com'
TIMEOUT = 3

FORMAT = '%(name)s:%(levelname)s %(module)s:%(lineno)d:%(asctime)s  %(message)s'
logger = logging.getLogger(__name__)


to_bytes = methodcaller('encode', 'utf-8')


def get_basic_auth_header(consumer_key, secret):
    k = quote(consumer_key)
    sc = quote(secret)
    return 'Basic ' + base64.b64encode(to_bytes('{0}:{1}'.format(k, sc))).decode('utf-8')


async def get_bearer_token(consumer_key,  secret):
    data = {'grant_type': 'client_credentials'}
    headers = {'Authorization': get_basic_auth_header(consumer_key, secret)}
    with aiohttp.Timeout(TIMEOUT):
        async with aiohttp.post(urljoin(API_URL, 'oauth2/token'), data=data, headers=headers) as r:
            if r.status == 200:
                j = await r.json()
                if j.get('token_type') == 'bearer':
                    return j.get('access_token')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    tw_group = parser.add_argument_group('Twitter options')

    tw_group.add_argument("--consumer-key", action="store", dest="consumer_key", required=True, help=u"Twitter consumer Key")

    tw_group.add_argument("--consumer-secret", action="store", dest="consumer_secret", required=True, help=u"Twitter consumer secret")

    parser.add_argument("--loglevel", action="store", dest="loglevel", default='DEBUG', choices=['DEBUG', 'INFO', 'WARNINGS', 'ERROR'], help=u"Log level")

    args = parser.parse_args()

    logging.basicConfig(stream=sys.stdout, format=FORMAT, level=getattr(logging, args.loglevel))

    loop = asyncio.get_event_loop()
    bearer = loop.run_until_complete(
       get_bearer_token(args.consumer_key, args.consumer_secret)
       )
    logger.info('Got %s', bearer)
