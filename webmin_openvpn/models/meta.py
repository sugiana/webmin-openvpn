import sqlalchemy as sa
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker
from ziggurat_foundations.models.base import BaseModel
from zope.sqlalchemy import register

# Recommended naming convention used by Alembic/SQLAlchemy
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

metadata = sa.MetaData(naming_convention=NAMING_CONVENTION)
Base = declarative_base(cls=BaseModel, metadata=metadata)

# Scoped session
DBSession = scoped_session(sessionmaker())
register(DBSession)
