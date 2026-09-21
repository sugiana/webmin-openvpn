from pyramid.authentication import AuthTktCookieHelper
from pyramid.authorization import (
    ACLHelper,
    Authenticated,
    Everyone,
    Allow,
    Deny,
    DENY_ALL,
    ALL_PERMISSIONS,
)
from pyramid.interfaces import ISecurityPolicy
from zope.interface import implementer

from .models.auth import UserService


@implementer(ISecurityPolicy)
class SecurityPolicy:
    """
    Authentication & Authorization policy for Pyramid.
    Uses AuthTkt cookies for session tickets and checks user roles against
    database.
    """

    def __init__(self, secret):
        self.authtkt = AuthTktCookieHelper(
            secret=secret,
            cookie_name='webmin_openvpn_auth',
            secure=False,
            timeout=86400 * 7,  # 7 days
            reissue_time=86400,
            http_only=True,
        )
        self.acl = ACLHelper()

    def identity(self, request):
        """
        Return the User object for the authenticated userid, or None.
        Cached on the request via reify or standard attribute check.
        """
        if hasattr(request, '_cached_user'):
            return request._cached_user

        userid = self.authenticated_userid(request)
        if userid is None:
            request._cached_user = None
            return None

        try:
            user = UserService.by_id(int(userid), db_session=request.dbsession)
            request._cached_user = user
            return user
        except Exception:
            request._cached_user = None
            return None

    def authenticated_userid(self, request):
        """
        Return the authenticated userid from the cookie, or None.
        """
        identity_data = self.authtkt.identify(request)
        if identity_data is None:
            return None
        return identity_data.get('userid')

    def remember(self, request, userid, **kw):
        """
        Return a list of headers to remember the userid.
        """
        return self.authtkt.remember(request, str(userid), **kw)

    def forget(self, request, **kw):
        """
        Return a list of headers to forget the user.
        """
        return self.authtkt.forget(request, **kw)

    def permits(self, request, context, permission):
        """
        Check whether the principals associated with the request are allowed
        the permission on the given context.
        """
        principals = self.effective_principals(request)
        return self.acl.permits(context, principals, permission)

    def effective_principals(self, request):
        """
        Calculate effective principals for the current user.
        """
        principals = [Everyone]
        user = self.identity(request)
        if user is not None:
            principals.append(Authenticated)
            principals.append(f"u:{user.id}")
            for group in user.groups:
                principals.append(f"g:{group.group_name}")
                # Support both 'publik' and 'public' aliases
                if group.group_name == 'publik':
                    principals.append("g:public")
                elif group.group_name == 'public':
                    principals.append("g:publik")
        return principals


class RootContext:
    """
    Root context providing default ACL rules.
    """

    def __init__(self, request):
        self.request = request

    @property
    def __acl__(self):
        return [
            (Allow, 'g:admin', ALL_PERMISSIONS),
            (Allow, 'g:admin', 'admin'),
            (Allow, 'g:admin', 'public'),
            (Allow, 'g:admin', 'view'),
            (Allow, 'g:publik', 'public'),
            (Allow, 'g:public', 'public'),
            (Allow, 'g:publik', 'view'),
            (Allow, 'g:public', 'view'),
            (Allow, Authenticated, 'authenticated'),
            DENY_ALL,
        ]


def includeme(config):
    settings = config.get_settings()
    auth_secret = settings.get(
        'auth.secret', 'openvpn_default_auth_secret_key_change_me')
    config.set_security_policy(SecurityPolicy(secret=auth_secret))
    config.set_root_factory(RootContext)

    # Provide request.user shortcut
    config.add_request_method(
        lambda r: r.identity,
        'user',
        reify=True,
    )
