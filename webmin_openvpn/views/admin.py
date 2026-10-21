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
from ..models.network import VPN
from ..utils import (
    run_system_command,
    sync_system_password,
    get_cert_details,
    list_client_certificates,
    is_linux_user_exists,
    get_system_stats,
    get_proxy_user,
    get_proxy_info,
    get_proxy_ports,
    set_proxy_user,
    revoke_user,
    is_proxy_file_exists,
    is_no_more_proxy,
    generate_totp_secret,
    generate_totp_qr_svg_base64,
    format_totp_secret,
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
    new_proxy_cmd = settings.get(
        'openvpn.new_proxy_cmd', '/usr/local/bin/new-proxy-user')
    proxy_file = settings.get(
        'openvpn.proxy_file', '/var/log/openvpn/proxy.txt')

    proxy_exists = is_proxy_file_exists(proxy_file)
    no_more_proxy = is_no_more_proxy(settings)
    show_proxy_option = not (proxy_exists and no_more_proxy)

    username = ''
    proxy = False
    cmd_output = None
    cmd_success = None

    if request.method == 'POST':
        username = request.params.get('username', '').strip().lower()
        password = request.params.get('password', '')
        proxy = bool(request.params.get('proxy')) \
            if show_proxy_option else False

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
            # build-client-cert [user] [proxy] login adduser pass=[password]
            cmd = [build_cert_cmd, username]
            if proxy:
                cmd.append('proxy')
            cmd.extend(['login', 'adduser', f'pass={password}'])

            return_code, output = run_system_command(cmd, timeout=180)
            cmd_output = output
            cmd_success = (return_code == 0)

            cert_path = os.path.join(client_dir, f"{username}.tgz")
            if cmd_success or os.path.exists(cert_path):
                # Update proxy.txt only if proxy was checked
                if proxy:
                    set_proxy_user(
                        username, new_proxy_cmd=new_proxy_cmd,
                        proxy_file=proxy_file)

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
        'proxy': proxy,
        'show_proxy_option': show_proxy_option,
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
    /etc/openvpn/client, IP dari /var/log/openvpn/ipp.txt,
    dan status proxy dari /var/log/openvpn/proxy.txt.
    """
    settings = request.registry.settings
    client_dir = settings.get('openvpn.client_dir', '/etc/openvpn/client')
    ipp_file = settings.get('openvpn.ipp_file', '/var/log/openvpn/ipp.txt')
    proxy_file = settings.get(
        'openvpn.proxy_file', '/var/log/openvpn/proxy.txt')

    proxy_exists = is_proxy_file_exists(proxy_file)
    no_more_proxy = is_no_more_proxy(settings)
    show_proxy_option = not (proxy_exists and no_more_proxy)

    clients = list_client_certificates(
        client_dir, ipp_file=ipp_file, proxy_file=proxy_file)
    proxy_user = get_proxy_user(proxy_file)

    # Status koneksi VPN dari tabel openvpn (diisi oleh cron)
    vpn_rows = request.dbsession.query(VPN).all()
    vpn_map = {row.nama: row for row in vpn_rows if row.nama}
    vpn_map_lower = {row.nama.lower(): row for row in vpn_rows if row.nama}

    for c in clients:
        u = c['username']
        vpn_item = vpn_map.get(u) or vpn_map_lower.get(u.lower())
        if vpn_item:
            status_str = 'ON' if vpn_item.terhubung else 'OFF'
            dt = vpn_item.perubahan
            if dt:
                try:
                    dt_str = dt.strftime('%d/%m/%Y %H:%M:%S')
                except Exception:
                    dt_str = str(dt)
            else:
                dt_str = '-'
            c['status'] = status_str
            c['status_time'] = dt_str
            c['terhubung'] = vpn_item.terhubung
            if (not c.get('ip') or c.get('ip') == '-') and vpn_item.ip:
                c['ip'] = vpn_item.ip
        else:
            c['status'] = None
            c['status_time'] = '-'
            c['terhubung'] = None

    proxy_user, reverse_proxy_ports = get_proxy_info(proxy_file)

    return {
        'user': request.user,
        'clients': clients,
        'client_dir': client_dir,
        'ipp_file': ipp_file,
        'proxy_file': proxy_file,
        'proxy_user': proxy_user,
        'show_proxy_option': show_proxy_option,
        'reverse_proxy_ports': reverse_proxy_ports,
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


@view_config(
    route_name='admin_set_proxy',
    permission='admin',
)
def admin_set_proxy_view(request):
    """
    Admin: Menjadikan user yang dipilih sebagai proxy aktif di proxy.txt.
    """
    username = request.matchdict.get('username', '').strip().lower()
    if not username or not re.match(r'^[a-z0-9_\-\.]+$', username):
        request.session.flash('Nama user tidak valid.', 'danger')
        return HTTPFound(location=request.route_url('admin_users'))

    settings = request.registry.settings
    proxy_file = settings.get(
        'openvpn.proxy_file', '/var/log/openvpn/proxy.txt')

    proxy_exists = is_proxy_file_exists(proxy_file)
    no_more_proxy = is_no_more_proxy(settings)
    if proxy_exists and no_more_proxy:
        request.session.flash('Opsi proxy dinonaktifkan.', 'warning')
        return HTTPFound(location=request.route_url('admin_users'))

    new_proxy_cmd = settings.get(
        'openvpn.new_proxy_cmd', '/usr/local/bin/new-proxy-user')

    success = set_proxy_user(
        username, new_proxy_cmd=new_proxy_cmd, proxy_file=proxy_file)
    if success:
        request.session.flash(
            f'User "{username}" berhasil diset sebagai proxy aktif.',
            'success',
        )
    else:
        request.session.flash(
            f'Gagal memperbarui proxy untuk "{username}".',
            'danger',
        )

    return HTTPFound(location=request.route_url('admin_users'))


@view_config(
    route_name='admin_reverse_proxy_ports',
    permission='admin',
)
def admin_reverse_proxy_ports_view(request):
    """
    Admin: Mengatur reverse proxy ports.
    Pilihan 1: /usr/local/bin/new-proxy-user [username]
    Pilihan 2: /usr/local/bin/new-proxy-user [username] [ports]
    """
    if request.method != 'POST':
        return HTTPFound(location=request.route_url('admin_users'))

    settings = request.registry.settings
    proxy_file = settings.get(
        'openvpn.proxy_file', '/var/log/openvpn/proxy.txt')
    new_proxy_cmd = settings.get(
        'openvpn.new_proxy_cmd', '/usr/local/bin/new-proxy-user')

    username = request.params.get('username', '').strip().lower()
    if not username:
        username = get_proxy_user(proxy_file)

    if not username:
        request.session.flash('Tidak ada user proxy yang aktif.', 'danger')
        return HTTPFound(location=request.route_url('admin_users'))

    mode = request.params.get('proxy_port_mode', 'all').strip()

    if mode == 'all':
        success = set_proxy_user(
            username,
            ports=None,
            new_proxy_cmd=new_proxy_cmd,
            proxy_file=proxy_file,
        )
        if success:
            request.session.flash(
                f'Pengaturan proxy untuk "{username}" berhasil disimpan: '
                'Forward semua port kecuali 22, 80, 443, 1194.',
                'success',
            )
        else:
            request.session.flash(
                f'Gagal memperbarui pengaturan proxy untuk "{username}".',
                'danger',
            )
    elif mode == 'custom':
        raw_ports = request.params.get('reverse_proxy_ports', '').strip()
        if not raw_ports:
            request.session.flash(
                'Port tidak boleh kosong jika memilih forward port tertentu.',
                'danger',
            )
            return HTTPFound(location=request.route_url('admin_users'))

        if not re.match(r'^[0-9,]+$', raw_ports):
            request.session.flash(
                'Format port tidak valid. Hanya angka dan koma yang '
                'diperbolehkan.',
                'danger',
            )
            return HTTPFound(location=request.route_url('admin_users'))

        port_list = [p.strip() for p in raw_ports.split(',') if p.strip()]
        if not port_list:
            request.session.flash(
                'Daftar port tidak boleh kosong.',
                'danger',
            )
            return HTTPFound(location=request.route_url('admin_users'))

        invalid_ports = []
        valid_ports = []
        for p in port_list:
            try:
                p_num = int(p)
                if 1 <= p_num <= 65535:
                    valid_ports.append(str(p_num))
                else:
                    invalid_ports.append(p)
            except ValueError:
                invalid_ports.append(p)

        if invalid_ports:
            request.session.flash(
                f'Nomor port tidak valid (harus antara 1 dan 65535): '
                f'{", ".join(invalid_ports)}',
                'danger',
            )
            return HTTPFound(location=request.route_url('admin_users'))

        ports_str = ",".join(valid_ports)
        success = set_proxy_user(
            username,
            ports=ports_str,
            new_proxy_cmd=new_proxy_cmd,
            proxy_file=proxy_file,
        )
        if success:
            request.session.flash(
                f'Pengaturan proxy untuk "{username}" berhasil disimpan: '
                f'Port {ports_str}.',
                'success',
            )
        else:
            request.session.flash(
                f'Gagal memperbarui pengaturan proxy untuk "{username}".',
                'danger',
            )
    else:
        request.session.flash('Pilihan mode port tidak valid.', 'danger')

    return HTTPFound(location=request.route_url('admin_users'))


@view_config(
    route_name='admin_revoke_user',
    renderer='webmin_openvpn:templates/admin/revoke_user.pt',
    permission='admin',
)
def admin_revoke_user_view(request):
    """
    Admin: Konfirmasi dan hapus (revoke) user OpenVPN.
    """
    username = request.matchdict.get('username', '').strip().lower()
    if not username or not re.match(r'^[a-z0-9_\-\.]+$', username):
        request.session.flash('Username tidak valid.', 'danger')
        return HTTPFound(location=request.route_url('admin_users'))

    settings = request.registry.settings
    client_dir = settings.get('openvpn.client_dir', '/etc/openvpn/client')
    revoke_cmd = settings.get(
        'openvpn.revoke_cmd', '/usr/local/bin/revoke-user')
    expected_text = f"Silakan hapus {username}"

    if request.method == 'POST':
        action = request.params.get('action', '')
        if action == 'cancel':
            return HTTPFound(location=request.route_url('admin_users'))

        confirm_text = request.params.get('confirm_text', '').strip()
        if confirm_text != expected_text:
            request.session.flash(
                f'Kalimat konfirmasi belum sesuai. '
                f'Harap ketik persis: "{expected_text}".',
                'danger',
            )
            return {
                'user': request.user,
                'target_username': username,
                'expected_text': expected_text,
                'user_input': confirm_text,
            }

        success, output = revoke_user(
            username, revoke_cmd=revoke_cmd, client_dir=client_dir)
        if success:
            request.session.flash(
                f'User "{username}" berhasil dihapus.',
                'success',
            )
            return HTTPFound(location=request.route_url('admin_users'))
        else:
            request.session.flash(
                f'Gagal menghapus user "{username}": {output}',
                'danger',
            )
            return {
                'user': request.user,
                'target_username': username,
                'expected_text': expected_text,
                'user_input': confirm_text,
            }

    return {
        'user': request.user,
        'target_username': username,
        'expected_text': expected_text,
        'user_input': '',
    }


@view_config(
    route_name='admin_2fa',
    renderer='webmin_openvpn:templates/admin/two_factor.pt',
    permission='admin',
)
def admin_2fa_view(request):
    """
    Admin: Two-Factor Authentication (2FA) Google Authenticator settings.
    Allows enabling and disabling TOTP-based 2FA.
    """
    user = request.user

    if request.method == 'POST':
        action = request.params.get('action', '')

        if action == 'disable':
            # Confirm with account password
            password = request.params.get('password', '')
            if not password:
                request.session.flash(
                    'Harap masukkan kata sandi akun Anda untuk konfirmasi.',
                    'danger',
                )
            elif not user.check_password(password):
                request.session.flash(
                    'Kata sandi yang Anda masukkan salah.', 'danger')
            else:
                user.totp_secret = None
                request.dbsession.flush()
                request.session.pop('pending_2fa_secret', None)
                request.session.flash(
                    'Two-Factor Authentication berhasil dinonaktifkan.',
                    'warning',
                )
                return HTTPFound(location=request.route_url('admin_2fa'))

        elif action == 'enable':
            token = request.params.get('token', '').strip().replace(' ', '')
            pending_secret = request.session.get('pending_2fa_secret')

            if not pending_secret:
                request.session.flash(
                    'Sesi pembuatan 2FA telah kedaluwarsa. Silakan ulangi.',
                    'warning',
                )
                return HTTPFound(location=request.route_url('admin_2fa'))

            if not token:
                request.session.flash(
                    'Harap masukkan 6 digit kode dari Google Authenticator.',
                    'danger',
                )
            elif len(token) != 6 or not token.isdigit():
                request.session.flash(
                    'Kode verifikasi harus terdiri dari 6 angka.', 'danger')
            else:
                import pyotp
                totp = pyotp.TOTP(pending_secret)
                if totp.verify(token, valid_window=1):
                    user.totp_secret = pending_secret
                    request.dbsession.flush()
                    request.session.pop('pending_2fa_secret', None)
                    request.session.flash(
                        'Two-Factor Authentication (Google Authenticator) '
                        'berhasil diaktifkan! Akun Anda kini lebih aman.',
                        'success',
                    )
                    return HTTPFound(location=request.route_url('admin_2fa'))
                else:
                    request.session.flash(
                        'Kode verifikasi tidak valid atau kedaluwarsa. '
                        'Pastikan jam di perangkat Android Anda tepat.',
                        'danger',
                    )

    # Prepare secret and QR code if 2FA is not yet active
    qr_svg = None
    formatted_secret = None
    raw_secret = None
    if not user.has_2fa:
        pending_secret = request.session.get('pending_2fa_secret')
        if not pending_secret:
            pending_secret = generate_totp_secret()
            request.session['pending_2fa_secret'] = pending_secret
        raw_secret = pending_secret
        formatted_secret = format_totp_secret(pending_secret)
        qr_svg = generate_totp_qr_svg_base64(
            pending_secret, user.user_name, issuer='WebminOpenVPN')

    return {
        'user': user,
        'qr_svg': qr_svg,
        'secret': raw_secret,
        'formatted_secret': formatted_secret,
    }


def includeme(config):
    config.add_route('admin_dashboard', '/admin')
    config.add_route('admin_change_password', '/admin/change-password')
    config.add_route('admin_2fa', '/admin/2fa')
    config.add_route('admin_create_cert', '/admin/create-cert')
    config.add_route('admin_users', '/admin/users')
    config.add_route(
        'admin_download_cert',
        '/admin/users/{username:[a-z0-9_\\-\\.]+}/download')
    config.add_route(
        'admin_edit_user_password',
        '/admin/users/{username:[a-z0-9_\\-\\.]+}/password')
    config.add_route(
        'admin_set_proxy',
        '/admin/users/{username:[a-z0-9_\\-\\.]+}/proxy')
    config.add_route('admin_reverse_proxy_ports', '/admin/users/proxy-ports')
    config.add_route(
        'admin_revoke_user',
        '/admin/users/{username:[a-z0-9_\\-\\.]+}/revoke')
    config.add_route('admin_system_stats', '/admin/api/system-stats')
    config.scan(__name__)
