# coding: utf-8
import argparse
import asyncio
import functools
import logging
import time
import sys
import urllib
from collections import namedtuple

from . app_only_client import get_timeline


logger = logging.getLogger(__name__)
TimelineOptions = namedtuple('TimelineOptions', 'count max_id since_id trim_user screen_name')
USER_URL = 'statuses/user_timeline.json'
HOME_URL = 'statuses/home_timeline.json'


class TimelineError(Exception):
    pass


class UserNotFound(TimelineError):
    pass


class TwitterError(TimelineError):
    pass


class Timeline(object):
    """Iterator over timeline"""
    def __init__(self, timeline_options, get_timeline_func, delay_func=asyncio.sleep, export_all=False, url=USER_URL):
        self._count = timeline_options.count
        self._max_id = timeline_options.max_id
        self._since_id = timeline_options.since_id
        self._trim_user = timeline_options.trim_user
        self._screen_name = timeline_options.screen_name
        self._get_timeline_func = get_timeline_func
        self._url = url
        self._first_request = True
        self._timeline = []
        self._export_all = export_all and not (timeline_options.max_id or timeline_options.since_id)
        self._delay = 0
        self._delay_func = delay_func

    @property
    def max_id(self):
        return self._max_id

    @property
    def since_id(self):
        return self._since_id

    @property
    def count(self):
        return self._count

    @property
    def screen_name(self):
        return self._screen_name

    @property
    def trim_user(self):
        return self._trim_user

    @property
    def url(self):
        return self._url

    def __repr__(self):
        return 'Timeline for {self._screen_name}, max_id: {self.max_id}, since_id: {self.since_id}, url: {self._url}'.format(self=self)

    def _prepare_options(self):
        o = dict()
        if self._max_id:
            o['max_id'] = self._max_id
        if self._since_id and self._first_request:
            o['since_id'] = self._since_id
        o['count'] = self._count
        o['trim_user'] = self._trim_user
        o['screen_name'] = self._screen_name
        return o

    def _check_response(self, resp):
        if resp.status not in (200, 429):
            if resp.status == 404:
                raise UserNotFound()
            else:
                raise TwitterError(u'Status is {0}'.format(resp.status))

        remaining = int(resp.headers['x-rate-limit-remaining'])
        if remaining == 0:
            reset = int(resp.headers['x-rate-limit-reset'])
            self._delay = reset - int(time.time())

    async def _get_user_timeline(self):
        if self._delay:
            logger.debug(u'Waiting %s secs', self._delay)
            self._delay_func(self._delay)
            self._delay = 0

        qs = urllib.parse.urlencode(self._prepare_options())
        url = '{0}?{1}'.format(self._url, qs)
        content, resp = await self._get_timeline_func(url)
        logger.debug(u'Url %s, got response %s', url, resp)
        self._check_response(resp)
        return content

    async def __anext__(self):
        if self._first_request:
            self._timeline = await self._get_user_timeline()
            self._since_id = self._timeline[0]['id'] if self._timeline else 0
            self._first_request = False
        elif not self._timeline and self._export_all:
            self._timeline = await self._get_user_timeline()

        if not self._timeline:
            raise StopAsyncIteration

        tw = self._timeline.pop(0)
        self._max_id = tw['id'] - 1
        return tw

    async def __aiter__(self):
        return self


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--loglevel", action="store", dest="loglevel", default='DEBUG', choices=['DEBUG', 'INFO', 'WARNINGS', 'ERROR'], help=u"Log level")

    tw_group = parser.add_argument_group('Twitter options')

    tw_group.add_argument("--consumer-key", action="store", dest="consumer_key", required=True, help=u"Twitter consumer Key")

    tw_group.add_argument("--consumer-secret", action="store", dest="consumer_secret", required=True, help=u"Twitter consumer secret")

    tw_group.add_argument("--auth-type", action="store", dest="auth_type", choices=['user_pin', 'app_only'], help="Auth type")

    parser.add_argument("--count", action="store", dest="count", default=10, help=u"Count")

    parser.add_argument("--max-id", action="store", dest="max_id", default=0, help=u"Max id")

    parser.add_argument("--since-id", action="store", dest="since_id", default=0, help=u"Since id")

    parser.add_argument("--trim-user", action="store", dest="trim_user", default=True, help=u"Trim user info")

    parser.add_argument("--screen-name", action="store", dest="screen_name",  help=u"Screen name")

    args = parser.parse_args()

    _format = '%(name)s:%(levelname)s %(module)s:%(lineno)d:%(asctime)s  %(message)s'
    logging.basicConfig(stream=sys.stdout, format=_format, level=getattr(logging, args.loglevel))

    timeline_options = TimelineOptions(args.count, args.max_id, args.since_id, args.trim_user, args.screen_name)

    if args.auth_type == 'user_pin':
        timeline = None
    elif args.auth_type == 'app_only':
        get_timeline_func = functools.partial(get_timeline, consumer_key=args.consumer_key, consumer_secret=args.consumer_secret)
        timeline = Timeline(timeline_options, get_timeline_func)

    async def print_timeline(timeline):
        async for t in timeline:
            print(t)

    logger.info('Starting')
    loop = asyncio.get_event_loop()
    if args.loglevel == 'DEBUG':
        loop.set_debug(True)
    loop.run_until_complete(print_timeline(timeline))
    loop.close()

    logger.info('Done')
