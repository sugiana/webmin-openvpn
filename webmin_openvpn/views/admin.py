import os
import re
from pyramid.view import view_config
from pyramid.response import FileResponse
from pyramid.httpexceptions import HTTPFound, HTTPNotFound

from ..models.auth import (
    User,
    Group,
    UserGroup,
    UserService,
    GroupService,
)
from ..utils import (
    run_system_command,
    sync_system_password,
    get_cert_details,
    list_client_certificates,
    is_linux_user_exists,
    get_system_stats,
)


@view_config(
    route_name='admin_dashboard',
    renderer='webmin_openvpn:templates/admin/dashboard.pt',
    permission='admin',
)
def admin_dashboard_view(request):
    """
    Admin dashboard with server and user overview.
    Users and certs are based on *.tgz files in the OpenVPN client directory.
    Includes initial system_stats for immediate rendering.
    """
    settings = request.registry.settings
    client_dir = settings.get('openvpn.client_dir', '/etc/openvpn/client')

    clients = list_client_certificates(client_dir)
    cert_count = len(clients)
    users_count = len(clients)

    # Sort by modification time descending for recent users
    recent_clients = sorted(
        clients, key=lambda c: c.get('mtime_epoch', 0), reverse=True)

    return {
        'user': request.user,
        'users_count': users_count,
        'cert_count': cert_count,
        'recent_users': recent_clients[:10],
        'client_dir': client_dir,
        'system_stats': get_system_stats(),
    }


@view_config(
    route_name='admin_change_password',
    renderer='webmin_openvpn:templates/admin/change_password.pt',
    permission='admin',
)
def admin_change_password_view(request):
    """
    Admin: Ubah password diri sendiri.
    """
    user = request.user
    if request.method == 'POST':
        current_password = request.params.get('current_password', '')
        new_password = request.params.get('new_password', '')
        confirm_password = request.params.get('confirm_password', '')

        if not current_password or not new_password or not confirm_password:
            request.session.flash(
                'Semua kolom password wajib diisi.', 'danger')
        elif not user.check_password(current_password):
            request.session.flash('Password saat ini salah.', 'danger')
        elif len(new_password) < 8:
            request.session.flash(
                'Password baru minimal 8 karakter.', 'danger')
        elif new_password != confirm_password:
            request.session.flash(
                'Konfirmasi password baru tidak cocok.', 'danger')
        else:
            # Update password in database
            user.set_password(new_password)
            request.dbsession.flush()

            # Sync system user password if exists
            sync_system_password(user.user_name, new_password)

            request.session.flash('Password Anda berhasil diubah!', 'success')
            return HTTPFound(location=request.route_url('admin_dashboard'))

    return {
        'user': user,
    }


@view_config(
    route_name='admin_create_cert',
    renderer='webmin_openvpn:templates/admin/create_cert.pt',
    permission='admin',
)
def admin_create_cert_view(request):
    """
    Admin: Membuat sertifikat OpenVPN.
    Input: username dan password.
    Menjalankan:
    build-client-cert [username] proxy login adduser pass=[password]
    Catatan: Tidak menambahkan user ke tabel database users (tidak ada public
    user portal).
    """
    settings = request.registry.settings
    client_dir = settings.get('openvpn.client_dir', '/etc/openvpn/client')
    build_cert_cmd = settings.get(
        'openvpn.build_cert_cmd', '/usr/local/bin/build-client-cert')

    username = ''
    cmd_output = None
    cmd_success = None

    if request.method == 'POST':
        username = request.params.get('username', '').strip().lower()
        password = request.params.get('password', '')

        # Validation
        if not username or not password:
            request.session.flash(
                'Username dan password wajib diisi.', 'danger')
        elif not re.match(r'^[a-z0-9-]+$', username):
            request.session.flash(
                'Username hanya boleh berisi huruf kecil, angka, '
                'dan karakter minus (-).', 'danger')
        elif is_linux_user_exists(username):
            request.session.flash(
                f'Username "{username}" sudah terdaftar di sistem Linux '
                f'(/etc/passwd). Silakan gunakan username lain.', 'danger')
        elif len(password) < 8:
            request.session.flash('Password minimal 8 karakter.', 'danger')
        else:
            # Build and execute command:
            # build-client-cert [username] proxy login adduser pass=[password]
            cmd = [
                build_cert_cmd,
                username,
                'proxy',
                'login',
                'adduser',
                f'pass={password}',
            ]

            return_code, output = run_system_command(cmd, timeout=180)
            cmd_output = output
            cmd_success = (return_code == 0)

            cert_path = os.path.join(client_dir, f"{username}.tgz")
            if cmd_success or os.path.exists(cert_path):
                request.session.flash(
                    f'Sertifikat OpenVPN untuk "{username}" berhasil dibuat!',
                    'success',
                )
            else:
                request.session.flash(
                    f'Gagal membuat sertifikat OpenVPN untuk "{username}". '
                    f'Kode error: {return_code}.', 'danger',
                )

    return {
        'user': request.user,
        'username': username,
        'cmd_output': cmd_output,
        'cmd_success': cmd_success,
        'client_dir': client_dir,
    }


@view_config(
    route_name='admin_users',
    renderer='webmin_openvpn:templates/admin/users.pt',
    permission='admin',
)
def admin_users_view(request):
    """
    Admin: Melihat daftar user dari file *.tgz di direktori
    /etc/openvpn/client.
    """
    settings = request.registry.settings
    client_dir = settings.get('openvpn.client_dir', '/etc/openvpn/client')

    clients = list_client_certificates(client_dir)

    return {
        'user': request.user,
        'clients': clients,
        'client_dir': client_dir,
    }


@view_config(
    route_name='admin_download_cert',
    permission='admin',
)
def admin_download_cert_view(request):
    """
    Admin: Unduh file sertifikat OpenVPN (.tgz).
    """
    username = request.matchdict.get('username', '').strip().lower()
    if not username or not re.match(r'^[a-z0-9_\-\.]+$', username):
        request.session.flash('Nama user tidak valid.', 'danger')
        return HTTPFound(location=request.route_url('admin_users'))

    settings = request.registry.settings
    client_dir = settings.get('openvpn.client_dir', '/etc/openvpn/client')
    cert_path = os.path.abspath(os.path.join(client_dir, f"{username}.tgz"))
    abs_client_dir = os.path.abspath(client_dir)

    # Security check to prevent directory traversal
    if not cert_path.startswith(abs_client_dir) or not os.path.exists(
            cert_path):
        request.session.flash(
            f'File sertifikat "{username}.tgz" '
            f'tidak ditemukan di direktori {client_dir}.',
            'warning',
        )
        return HTTPFound(location=request.route_url('admin_users'))

    try:
        response = FileResponse(
            cert_path,
            request=request,
            content_type='application/gzip',
        )
        response.headers['Content-Disposition'] = (
            f'attachment; filename="{username}.tgz"')
        return response
    except Exception as e:
        request.session.flash(
            f'Gagal mengunduh file sertifikat: {e}', 'danger')
        return HTTPFound(location=request.route_url('admin_users'))


@view_config(
    route_name='admin_edit_user_password',
    renderer='webmin_openvpn:templates/admin/edit_user_password.pt',
    permission='admin',
)
def admin_edit_user_password_view(request):
    """
    Admin: Mengubah password user OpenVPN / sistem Linux.
    """
    username = request.matchdict.get('username', '').strip().lower()
    if not username or not re.match(r'^[a-z0-9_\-\.]+$', username):
        request.session.flash('Username tidak valid.', 'danger')
        return HTTPFound(location=request.route_url('admin_users'))

    settings = request.registry.settings
    client_dir = settings.get('openvpn.client_dir', '/etc/openvpn/client')
    cert_info = get_cert_details(client_dir, username)

    if request.method == 'POST':
        new_password = request.params.get('new_password', '')
        confirm_password = request.params.get('confirm_password', '')

        if not new_password or not confirm_password:
            request.session.flash(
                'Password baru dan konfirmasi wajib diisi.', 'danger')
        elif len(new_password) < 8:
            request.session.flash('Password minimal 8 karakter.', 'danger')
        elif new_password != confirm_password:
            request.session.flash('Konfirmasi password tidak cocok.', 'danger')
        else:
            # 1. Sync system Linux user password (used by OpenVPN PAM)
            sync_res, sync_msg = sync_system_password(username, new_password)

            # 2. Update DB user password if user exists in database
            db_user = UserService.by_user_name(
                username, db_session=request.dbsession)
            if db_user:
                db_user.set_password(new_password)
                request.dbsession.flush()

            if sync_res:
                request.session.flash(
                    f'Password untuk user "{username}" berhasil diubah!',
                    'success',
                )
                return HTTPFound(location=request.route_url('admin_users'))
            else:
                request.session.flash(
                    'Gagal mengubah password sistem '
                    f'untuk "{username}": {sync_msg}',
                    'danger',
                )

    return {
        'user': request.user,
        'target_username': username,
        'cert_info': cert_info,
    }


@view_config(
    route_name='admin_system_stats',
    renderer='json',
    permission='admin',
)
def admin_system_stats_view(request):
    """
    API endpoint returning real-time system metrics (CPU, RAM, Swap, Disk,
    Network).
    Called by front-end dashboard every 1 second.
    """
    return get_system_stats()


def includeme(config):
    config.add_route('admin_dashboard', '/admin')
    config.add_route('admin_change_password', '/admin/change-password')
    config.add_route('admin_create_cert', '/admin/create-cert')
    config.add_route('admin_users', '/admin/users')
    config.add_route(
        'admin_download_cert',
        '/admin/users/{username:[a-z0-9_\\-\\.]+}/download')
    config.add_route(
        'admin_edit_user_password',
        '/admin/users/{username:[a-z0-9_\\-\\.]+}/password')
    config.add_route('admin_system_stats', '/admin/api/system-stats')
    config.scan(__name__)
