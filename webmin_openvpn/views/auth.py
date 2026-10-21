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
                target_url = request.params.get('next') or request.route_url(
                    'admin_dashboard')
                if user.has_2fa:
                    # Require step 2 TOTP verification
                    request.session['2fa_pending_user_id'] = user.id
                    request.session['2fa_pending_next'] = target_url
                    return HTTPFound(location=request.route_url('login_2fa'))

                # Successful authentication without 2FA
                headers = remember(request, str(user.id))
                request.session.flash(
                    f'Selamat datang kembali, {user.user_name}!', 'success')
                return HTTPFound(location=target_url, headers=headers)
            else:
                request.session.flash(
                    'Username atau password tidak valid.', 'danger')

    return {
        'username': username,
        'next_url': next_url,
    }


@view_config(
    route_name='login_2fa',
    renderer='webmin_openvpn:templates/login_2fa.pt',
)
def login_2fa_view(request):
    """
    Handle Step 2: Google Authenticator TOTP verification.
    """
    if request.user:
        return HTTPFound(location=request.route_url('admin_dashboard'))

    user_id = request.session.get('2fa_pending_user_id')
    if not user_id:
        request.session.flash(
            'Sesi autentikasi telah berakhir. Silakan login kembali.',
            'warning')
        return HTTPFound(location=request.route_url('login'))

    user = UserService.by_id(user_id, db_session=request.dbsession)
    if not user or not user.is_admin or not user.has_2fa:
        request.session.pop('2fa_pending_user_id', None)
        request.session.pop('2fa_pending_next', None)
        request.session.flash('Sesi autentikasi tidak valid.', 'danger')
        return HTTPFound(location=request.route_url('login'))

    if request.method == 'POST':
        action = request.params.get('action')
        if action == 'cancel':
            request.session.pop('2fa_pending_user_id', None)
            request.session.pop('2fa_pending_next', None)
            return HTTPFound(location=request.route_url('login'))

        token = request.params.get('token', '').strip().replace(' ', '')
        if not token:
            request.session.flash(
                'Harap masukkan kode 6 digit dari Google Authenticator.',
                'danger',
            )
        elif len(token) != 6 or not token.isdigit():
            request.session.flash(
                'Kode verifikasi harus terdiri dari 6 angka.', 'danger')
        elif user.verify_totp(token):
            request.session.pop('2fa_pending_user_id', None)
            target_url = request.session.pop(
                '2fa_pending_next', None) or request.route_url(
                'admin_dashboard')
            headers = remember(request, str(user.id))
            request.session.flash(
                f'Selamat datang kembali, {user.user_name}!', 'success')
            return HTTPFound(location=target_url, headers=headers)
        else:
            request.session.flash(
                'Kode verifikasi tidak valid atau telah kedaluwarsa. '
                'Pastikan jam di perangkat Android Anda tepat.',
                'danger',
            )

    return {
        'username': user.user_name,
    }


@view_config(route_name='logout')
def logout_view(request):
    """
    Handle user logout.
    """
    headers = forget(request)
    request.session.pop('2fa_pending_user_id', None)
    request.session.pop('2fa_pending_next', None)
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
    config.add_route('login_2fa', '/login/2fa')
    config.add_route('logout', '/logout')
    config.scan(__name__)
