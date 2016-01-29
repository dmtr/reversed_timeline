# coding: utf-8
import argparse
import logging
import time
import sys
import urllib
from collections import namedtuple

import simplejson
from aioauth_client import TwitterClient


FORMAT = '%(name)s:%(levelname)s %(module)s:%(lineno)d:%(asctime)s  %(message)s'
logger = logging.getLogger(__name__)
TimelineOptions = namedtuple('TimelineOptions', 'count max_id since_id trim_user')


def send_oauth_req(url, consumer_key, consumer_secret, token, token_secret=None):
    twitter = TwitterClient(
        consumer_key,
        consumer_secret,
        token,
        token_secret
    )

    timeline = yield from twitter.request('GET', url)
    content = yield from timeline.read()
    return content


class Timeline(object):
    """Iterator over timeline"""
    def __init__(self, consumer_key, consumer_secret, token, timeline_options, delay_func=time.sleep):
        self._consumer_key = consumer_key
        self._consumer_secret = consumer_secret
        self._token = token
        self._count = timeline_options.count
        self._max_id = timeline_options.max_id
        self._since_id = timeline_options.since_id
        self._trim_user = timeline_options.trim_user
        self._first_request = True
        self._timeline = []
        self._export_all = not (timeline_options.max_id or timeline_options.since_id)
        self._delay = 0
        self._delay_func = delay_func

    @property
    def max_id(self):
        return self._max_id

    @property
    def since_id(self):
        return self._since_id

    def __repr__(self):
        return 'Timeline, max_id: {self.max_id}, since_id: {self.since_id}'.format(self=self)

    def _prepare_options(self):
        o = dict()
        if self._max_id:
            o['max_id'] = self._max_id
        if self._since_id and self._first_request:
            o['since_id'] = self._since_id
        o['count'] = self._count
        o['trim_user'] = self._trim_user
        return o

    def _check_response(self, resp):
        if resp['status'] not in ('200', '429'):
            raise Exception(u'Status is {0}'.format(resp['status']))

        remaining = int(resp['x-rate-limit-remaining'])
        if remaining == 0:
            reset = int(resp['x-rate-limit-reset'])
            self._delay = reset - int(time.time())

    def _get_user_timeline(self):
        if self._delay:
            logger.debug(u'Waiting %s secs', self._delay)
            self._delay_func(self._delay)
            self._delay = 0

        qs = urllib.urlencode(self._prepare_options())
        url = '/statuses/user_timeline.json'
        if qs:
            url = '{0}?{1}'.format(url, qs)
        content = send_oauth_req(url, self._consumer_key, self._consumer_secret, self._token)
        logger.debug(u'Url %s, got response %s', url, content)
        # self._check_response(resp)
        return simplejson.loads(content)

    def next(self):
        if self._first_request:
            self._timeline = self._get_user_timeline()
            self._since_id = self._timeline[0]['id'] if self._timeline else 0
            self._first_request = False
        elif not self._timeline and self._export_all:
            self._timeline = self._get_user_timeline()

        if not self._timeline:
            raise StopIteration

        tw = self._timeline.pop(0)
        self._max_id = tw['id'] - 1
        return tw

    def __iter__(self):
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

    args = parser.parse_args()

    logging.basicConfig(stream=sys.stdout, format=FORMAT, level=getattr(logging, args.loglevel))
    handler = logging.handlers.RotatingFileHandler(__name__, maxBytes=10 * 1024 * 1024, backupCount=1000)
    fmt = logging.Formatter(FORMAT)
    handler.setFormatter(fmt)
    logger.setLevel(getattr(logging, args.loglevel))
    logger.addHandler(handler)

    timeline_options = TimelineOptions(args.count, args.max_id, args.since_id, args.trim_user)

    if args.auth_type == 'user_pin':
        timeline = None
    elif args.auth_type == 'app_only':
        timeline = None

    logger.info('Starting')
    try:
        for t in timeline:
            logger.info(u'Got tweet %s from timeline %s', t, timeline)
    except Exception as e:
        logger.error(u'Got error %s', e)
    logger.info('Done')
