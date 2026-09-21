import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
import zope.sqlalchemy

from .meta import Base, DBSession
from .auth import (
    User,
    Group,
    UserGroup,
    GroupPermission,
    UserPermission,
    Resource,
    UserResourcePermission,
    GroupResourcePermission,
    ExternalIdentity,
    UserService,
    GroupService,
)


def get_engine(settings, prefix='sqlalchemy.'):
    return sa.engine_from_config(settings, prefix)


def get_session_factory(engine):
    factory = sessionmaker()
    factory.configure(bind=engine)
    return factory


def get_tm_session(session_factory, transaction_manager, request=None):
    """
    Get a ``sqlalchemy.orm.Session`` instance backed by a transaction.
    """
    dbsession = session_factory()
    zope.sqlalchemy.register(
        dbsession, transaction_manager=transaction_manager
    )
    return dbsession


def includeme(config):
    """
    Initialize the model for a Pyramid app.
    """
    settings = config.get_settings()
    settings['tm.manager_hook'] = 'pyramid_tm.explicit_manager'

    # use pyramid_tm to manage transactions
    config.include('pyramid_tm')

    session_factory = get_session_factory(get_engine(settings))
    config.registry['dbsession_factory'] = session_factory

    # make request.dbsession available for use in Pyramid
    config.add_request_method(
        # r.tm is the transaction manager used by pyramid_tm
        lambda r: get_tm_session(session_factory, r.tm, request=r),
        'dbsession',
        reify=True,
    )
