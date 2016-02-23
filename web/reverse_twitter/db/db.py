
import logging

import rethinkdb as r
from rethinkdb.errors import RqlRuntimeError, RqlDriverError

logger = logging.getLogger(__name__)

TABLES = ('user', 'timeline')


def setup(config):
    connection = r.connect(host=config['rdb']['host'], port=config['rdb'].getint('port'))
    try:
        dbname = config['rdb']['dbname']
        r.db_create(dbname).run(connection)
        for t in TABLES:
            r.db(dbname).table_create(t).run(connection)
        logger.info('Database setup completed.')
    except RqlRuntimeError:
        logger.info('App database already exists.')
    finally:
        connection.close()


def get_connection(config):
    try:
        return r.connect(host=config['rdb']['host'], port=config['rdb'].getint('port'), db=config['rdb']['dbname'])
    except RqlDriverError:
        logger.error('No database connection could be established.')
