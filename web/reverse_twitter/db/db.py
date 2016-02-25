
import logging

import rethinkdb as r
from rethinkdb.errors import RqlRuntimeError, RqlDriverError, ReqlOpFailedError

logger = logging.getLogger(__name__)

TABLES = (('user', []), ('session', []))

migrations = set()


def migration(f):
    migrations.add(f)
    return f


def migrate(conn, dbname):
    logger.info('Running migrations')
    try:
        r.db(dbname).table_create('migration').run(conn)
        r.db(dbname).table('migration').index_create('name').run(conn)
        r.db(dbname).table('migration').index_wait().run(conn)
    except ReqlOpFailedError:
        pass

    c = r.db(dbname).table('migration').pluck('name').run(conn)
    existing = set([d['name'] for d in c])
    for m in migrations:
        if m.__name__ in existing:
            continue
        logger.info('Going to apply migration %s', m.__name__)
        m(conn, dbname)
        r.db(dbname).table('migration').insert({
            'name': m.__name__,
            'timestamp': r.now()
        }).run(conn)
    logger.info('Migrations done')


def setup(config):
    connection = r.connect(host=config['rdb']['host'], port=config['rdb'].getint('port'))
    dbname = config['rdb']['dbname']
    try:
        r.db_create(dbname).run(connection)
    except RqlRuntimeError:
        logger.info('App database already exists.')
        migrate(connection, dbname)
    else:
        for t in TABLES:
            name, indexes = t
            r.db(dbname).table_create(name).run(connection)
            for index in indexes:
                logger.info('Creating index %s', index)
                r.db(dbname).table(name).index_create(index).run(connection)
            r.db(dbname).table(name).index_wait().run(connection)
        logger.info('Database setup completed.')
    finally:
        connection.close()


def get_connection(config):
    try:
        return r.connect(host=config['rdb']['host'], port=config['rdb'].getint('port'), db=config['rdb']['dbname'])
    except RqlDriverError:
        logger.error('No database connection could be established.')
