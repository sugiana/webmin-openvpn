from pyramid.view import (
    view_config,
    forbidden_view_config,
    notfound_view_config,
    )
from pyramid.httpexceptions import HTTPFound
from pyramid.security import remember, forget

from ..models.auth import UserService


@view_config(route_name='login', renderer='webmin_openvpn:templates/login.pt')
def login_view(request):
    """
    Handle user authentication.
    """
    # If already logged in, redirect to admin dashboard
    if request.user:
        return HTTPFound(location=request.route_url('admin_dashboard'))

    next_url = request.params.get('next') or request.route_url(
        'admin_dashboard')
    username = ''

    if request.method == 'POST':
        username = request.params.get('username', '').strip()
        password = request.params.get('password', '')

        if not username or not password:
            request.session.flash(
                'Harap masukkan username dan password.', 'danger')
        else:
            user = UserService.by_user_name(
                    username, db_session=request.dbsession)
            if user and user.is_admin and user.check_password(password):
                # Successful authentication
                headers = remember(request, str(user.id))
                request.session.flash(
                    f'Selamat datang kembali, {user.user_name}!', 'success')
                target_url = request.params.get('next') or request.route_url(
                    'admin_dashboard')
                return HTTPFound(location=target_url, headers=headers)
            else:
                request.session.flash(
                    'Username atau password tidak valid.', 'danger')

    return {
        'username': username,
        'next_url': next_url,
    }


@view_config(route_name='logout')
def logout_view(request):
    """
    Handle user logout.
    """
    headers = forget(request)
    request.session.flash('Anda telah berhasil keluar.', 'info')
    return HTTPFound(location=request.route_url('login'), headers=headers)


@forbidden_view_config(renderer='webmin_openvpn:templates/errors/403.pt')
def forbidden_view(request):
    """
    Handle 403 Forbidden errors.
    If anonymous, redirect to login page.
    If authenticated, show 403 error page.
    """
    if not request.user:
        request.session.flash(
            'Silakan login terlebih dahulu untuk mengakses halaman tersebut.',
            'warning')
        login_url = request.route_url('login', _query={'next': request.url})
        return HTTPFound(location=login_url)

    request.response.status = 403
    return {
        'user': request.user,
        'message': 'Anda tidak memiliki hak akses untuk membuka halaman ini.',
    }


@notfound_view_config(renderer='webmin_openvpn:templates/errors/404.pt')
def notfound_view(request):
    """
    Handle 404 Not Found errors.
    """
    request.response.status = 404
    return {
        'user': request.user,
        'message': 'Halaman yang Anda tuju tidak ditemukan.',
    }


def includeme(config):
    config.add_route('login', '/login')
    config.add_route('logout', '/logout')
    config.scan(__name__)
