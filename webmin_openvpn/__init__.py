from pyramid.config import Configurator
from pyramid.session import SignedCookieSessionFactory


def main(global_config, **settings):
    """
    This function returns a Pyramid WSGI application.
    """
    # Configure session factory for flash messages and user sessions
    session_secret = settings.get(
        'session.secret', 'openvpn_default_session_secret_key_123')
    session_factory = SignedCookieSessionFactory(
        session_secret, cookie_name='webmin_openvpn_session')
    with Configurator(
            settings=settings, session_factory=session_factory) as config:
        # Chameleon template engine
        config.include('pyramid_chameleon')
        # Static assets
        config.add_static_view(
            'static', 'webmin_openvpn:static', cache_max_age=3600)
        # Database models & transaction management
        config.include('.models')
        # Security policy and ACL
        config.include('.security')
        # Routing and Views
        config.include('.views')
        config.scan(ignore='webmin_openvpn.tests')
        return config.make_wsgi_app()
