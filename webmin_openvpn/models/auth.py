import os
import sqlalchemy as sa
from sqlalchemy.orm import joinedload
from ziggurat_foundations import ziggurat_model_init
from ziggurat_foundations.models.user import UserMixin
from ziggurat_foundations.models.group import GroupMixin
from ziggurat_foundations.models.user_group import UserGroupMixin
from ziggurat_foundations.models.group_permission import GroupPermissionMixin
from ziggurat_foundations.models.user_permission import UserPermissionMixin
from ziggurat_foundations.models.resource import ResourceMixin
from ziggurat_foundations.models.user_resource_permission import (
    UserResourcePermissionMixin,
    )
from ziggurat_foundations.models.group_resource_permission import (
    GroupResourcePermissionMixin,
    )
from ziggurat_foundations.models.external_identity import ExternalIdentityMixin
from ziggurat_foundations.models.services.user import (
    UserService as ZigguratUserService,
    get_db_session,
)
from ziggurat_foundations.models.services.group import (
    GroupService as ZigguratGroupService,
)

from .meta import Base


class User(UserMixin, Base):
    """
    User model representing application and VPN users.
    """
    __tablename__ = 'users'

    def set_password(self, raw_password):
        UserService.set_password(self, raw_password)

    def check_password(self, raw_password):
        return UserService.check_password(self, raw_password)

    @property
    def is_admin(self):
        return any(g.group_name == 'admin' for g in self.groups)

    def get_cert_path(self, client_dir='/etc/openvpn/client'):
        return os.path.join(client_dir, f"{self.user_name}.tgz")

    def has_cert(self, client_dir='/etc/openvpn/client'):
        return os.path.exists(self.get_cert_path(client_dir))


class Group(GroupMixin, Base):
    """
    Group model for permission management (e.g., admin, publik).
    """
    __tablename__ = 'groups'


class UserGroup(UserGroupMixin, Base):
    """
    Association between Users and Groups.
    """
    __tablename__ = 'users_groups'


class GroupPermission(GroupPermissionMixin, Base):
    """
    Permissions assigned to Groups.
    """
    __tablename__ = 'groups_permissions'


class UserPermission(UserPermissionMixin, Base):
    """
    Direct permissions assigned to Users.
    """
    __tablename__ = 'users_permissions'


class Resource(ResourceMixin, Base):
    """
    Resource model for hierarchical permissions.
    """
    __tablename__ = 'resources'


class UserResourcePermission(UserResourcePermissionMixin, Base):
    """
    Resource permissions for Users.
    """
    __tablename__ = 'users_resources_permissions'


class GroupResourcePermission(GroupResourcePermissionMixin, Base):
    """
    Resource permissions for Groups.
    Overriding constraint name to avoid duplicate primary key name in
    PostgreSQL.
    """
    __tablename__ = 'groups_resources_permissions'
    __table_args__ = (
        sa.PrimaryKeyConstraint(
            'group_id', 'resource_id', 'perm_name',
            name='pk_groups_resources_permissions',
        ),
        {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8'},
    )


class ExternalIdentity(ExternalIdentityMixin, Base):
    """
    External identity model (OAuth / external auth).
    """
    __tablename__ = 'external_identities'


class UserService(ZigguratUserService):
    """
    Extended UserService with SQLAlchemy 2.0 compatibility.
    """

    @classmethod
    def by_user_name(cls, user_name, db_session=None):
        db_session = get_db_session(db_session)
        query = db_session.query(cls.model)
        query = query.filter(
            sa.func.lower(cls.model.user_name) == (user_name or "").lower()
        )
        query = query.options(joinedload(cls.model.groups))
        return query.first()

    @classmethod
    def by_id(cls, user_id, db_session=None):
        db_session = get_db_session(db_session)
        query = db_session.query(cls.model)
        query = query.filter(cls.model.id == user_id)
        query = query.options(joinedload(cls.model.groups))
        return query.first()

    @classmethod
    def by_email(cls, email, db_session=None):
        db_session = get_db_session(db_session)
        query = db_session.query(cls.model)
        query = query.filter(
            sa.func.lower(cls.model.email) == (email or "").lower()
        )
        query = query.options(joinedload(cls.model.groups))
        return query.first()

    @classmethod
    def all(cls, db_session=None):
        db_session = get_db_session(db_session)
        return (
            db_session.query(cls.model)
            .options(joinedload(cls.model.groups))
            .order_by(cls.model.id.asc())
            .all()
        )


class GroupService(ZigguratGroupService):
    """
    Extended GroupService with SQLAlchemy 2.0 compatibility.
    """

    @classmethod
    def by_group_name(cls, group_name, db_session=None):
        db_session = get_db_session(db_session)
        query = db_session.query(cls.model)
        query = query.filter(
            sa.func.lower(cls.model.group_name) == (group_name or "").lower()
        )
        return query.first()

    @classmethod
    def all(cls, db_session=None):
        db_session = get_db_session(db_session)
        return db_session.query(cls.model).order_by(cls.model.id.asc()).all()


# Initialize ziggurat models and attach them to services
ziggurat_model_init(
    user=User,
    group=Group,
    user_group=UserGroup,
    group_permission=GroupPermission,
    user_permission=UserPermission,
    user_resource_permission=UserResourcePermission,
    group_resource_permission=GroupResourcePermission,
    resource=Resource,
    external_identity=ExternalIdentity,
)

__all__ = [
    'Base',
    'User',
    'Group',
    'UserGroup',
    'GroupPermission',
    'UserPermission',
    'Resource',
    'UserResourcePermission',
    'GroupResourcePermission',
    'ExternalIdentity',
    'UserService',
    'GroupService',
]
