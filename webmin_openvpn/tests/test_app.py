import os
import tempfile
import shutil
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
import webtest
from pyramid.paster import get_appsettings
from webmin_openvpn import main
from webmin_openvpn.models import (
    get_engine,
    get_session_factory,
    User,
    UserService,
    VPN,
    )


class TestWebminOpenVPN(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ini_path = os.path.abspath('test.ini')
        settings = get_appsettings(ini_path)
        try:
            import psycopg2
            conn = psycopg2.connect(settings.get('sqlalchemy.url', ''))
            conn.close()
        except Exception:
            settings['sqlalchemy.url'] = \
                'postgresql://sugiana:a@/openvpn?host=/var/run/postgresql'

        # Setup isolated temp client dir with a test cert
        cls.test_client_dir = tempfile.mkdtemp()
        settings['openvpn.client_dir'] = cls.test_client_dir
        dummy_cert_path = os.path.join(cls.test_client_dir, 'sampleuser.tgz')
        with open(dummy_cert_path, 'wb') as f:
            f.write(b'dummy gzip content for test')

        cls.test_ipp_file = os.path.join(cls.test_client_dir, 'test_ipp.txt')
        with open(cls.test_ipp_file, 'w') as f:
            f.write("sampleuser,10.8.41.99,\notheruser,10.8.41.100,\n")
        settings['openvpn.ipp_file'] = cls.test_ipp_file

        cls.test_proxy_file = os.path.join(
            cls.test_client_dir, 'test_proxy.txt')
        with open(cls.test_proxy_file, 'w') as f:
            f.write("sampleuser\n")
        settings['openvpn.proxy_file'] = cls.test_proxy_file

        cls.test_blacklist_file = os.path.join(
            cls.test_client_dir, 'blacklist')
        cls.test_whitelist_file = os.path.join(
            cls.test_client_dir, 'whitelist')
        settings['openvpn.blacklist_file'] = cls.test_blacklist_file
        settings['openvpn.whitelist_file'] = cls.test_whitelist_file

        cls.test_firewall_cmd = os.path.join(
            cls.test_client_dir, 'dummy_firewall.sh')
        with open(cls.test_firewall_cmd, 'w') as f:
            f.write(
                "#!/bin/sh\necho 'Firewall dummy output: "
                "rules applied'\nexit 0\n")
        os.chmod(cls.test_firewall_cmd, 0o755)
        settings['openvpn.firewall_cmd'] = cls.test_firewall_cmd

        cls.app = main({}, **settings)
        cls.engine = get_engine(settings)
        cls.session_factory = get_session_factory(cls.engine)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.test_client_dir):
            shutil.rmtree(cls.test_client_dir)

    def setUp(self):
        self.testapp = webtest.TestApp(self.app)
        self.dbsession = self.session_factory()
        admin = UserService.by_user_name('admin', db_session=self.dbsession)
        if admin and admin.totp_secret:
            admin.totp_secret = None
            self.dbsession.commit()
        with open(self.test_proxy_file, 'w') as f:
            f.write("sampleuser\n")

    def tearDown(self):
        admin = UserService.by_user_name('admin', db_session=self.dbsession)
        if admin and admin.totp_secret:
            admin.totp_secret = None
            self.dbsession.commit()
        self.dbsession.close()

    def test_anonymous_redirect(self):
        """Anonymous access to / or /admin should redirect to login."""
        res_admin = self.testapp.get('/admin', status=302)
        self.assertIn('/login', res_admin.location)

        res_home = self.testapp.get('/', status=302)
        self.assertIn('/admin', res_home.location)
        follow_res = res_home.follow(status=302)
        self.assertIn('/login', follow_res.location)

    def test_login_page_renders(self):
        """Login page should render form with Chameleon template."""
        res = self.testapp.get('/login', status=200)
        self.assertIn('Masuk ke Portal', res.text)
        self.assertIn('name="username"', res.text)
        self.assertIn('name="password"', res.text)

    def test_admin_login_and_dashboard(self):
        """Admin user login and access to /admin dashboard."""
        # 1. Login with wrong password
        res = self.testapp.post(
            '/login', {'username': 'admin', 'password': 'wrongpassword'},
            status=200)
        self.assertIn('Username atau password tidak valid', res.text)

        # 2. Login with correct admin password
        res = self.testapp.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)
        self.assertIn('/admin', res.location)

        # 3. Follow redirect to /admin
        admin_page = res.follow(status=200)
        self.assertIn('Dashboard Administrator', admin_page.text)
        self.assertIn('sampleuser', admin_page.text)

    def test_admin_users_list_and_download(self):
        """Test listing users from .tgz directory and downloading
        certificate."""
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        # 1. Access /admin/users
        users_page = admin_app.get('/admin/users', status=200)
        self.assertIn('Data Klien OpenVPN', users_page.text)
        self.assertIn('sampleuser', users_page.text)
        self.assertIn('<th>Waktu Pembuatan</th>', users_page.text)
        self.assertNotIn('<th>Berkas Sertifikat (.tgz)</th>', users_page.text)
        self.assertIn('<th>IP Sumber</th>', users_page.text)
        self.assertIn('<th>IP VPN</th>', users_page.text)
        self.assertNotIn('<th>IP</th>', users_page.text)
        self.assertNotIn('<th>Ukuran</th>', users_page.text)
        self.assertIn('10.8.41.99', users_page.text)
        self.assertIn('Proxy', users_page.text)

        # 2. Download certificate
        dl_res = admin_app.get('/admin/users/sampleuser/download', status=200)
        self.assertEqual(dl_res.content_type, 'application/gzip')
        self.assertIn(
            'attachment; filename="sampleuser.tgz"',
            dl_res.headers.get('Content-Disposition', ''))
        self.assertEqual(dl_res.body, b'dummy gzip content for test')

        # 3. Non-existent user cert download redirects to users list
        dl_none = admin_app.get(
            '/admin/users/nonexistentuser/download', status=302)
        self.assertIn('/admin/users', dl_none.location)

    def test_admin_set_proxy(self):
        """Test clicking Proxy button sets user via set_proxy_user."""
        from unittest.mock import patch
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        # Allow proxy option for this test
        orig_setting = self.app.registry.settings.get('openvpn.no_more_proxy')
        self.app.registry.settings['openvpn.no_more_proxy'] = False
        try:
            # 1. Click Proxy button for sampleuser
            with patch('webmin_openvpn.views.admin.set_proxy_user') \
                    as mock_set:
                mock_set.return_value = True
                res = admin_app.get(
                    '/admin/users/sampleuser/proxy', status=302)
                self.assertIn('/admin/users', res.location)
                mock_set.assert_called_once()
                self.assertEqual(mock_set.call_args[0][0], 'sampleuser')

            # Follow redirect and verify success message and button
            followed = res.follow(status=200)
            self.assertIn('berhasil diset sebagai proxy aktif', followed.text)
            self.assertIn('Proxy', followed.text)
        finally:
            self.app.registry.settings['openvpn.no_more_proxy'] = orig_setting

    def test_load_ipp_map(self):
        """Test parsing OpenVPN ipp.txt file."""
        from webmin_openvpn.utils import load_ipp_map
        ipp_map = load_ipp_map(self.test_ipp_file)
        self.assertEqual(ipp_map.get('sampleuser'), '10.8.41.99')
        self.assertEqual(ipp_map.get('otheruser'), '10.8.41.100')
        self.assertIsNone(ipp_map.get('nonexistent'))

        # Non-existent file gracefully returns empty dict
        empty_map = load_ipp_map('/nonexistent/path/ipp.txt')
        self.assertEqual(empty_map, {})

    def test_admin_edit_user_password(self):
        """Test admin editing a user password."""
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        # 1. Open edit password form for sampleuser
        edit_page = admin_app.get(
            '/admin/users/sampleuser/password', status=200)
        self.assertIn('sampleuser', edit_page.text)
        self.assertIn('Ubah Password User OpenVPN', edit_page.text)

        # 2. Submit password mismatch validation
        fail_res = admin_app.post('/admin/users/sampleuser/password', {
            'new_password': 'password123',
            'confirm_password': 'mismatchpassword',
        }, status=200)
        self.assertIn(
            'Konfirmasi password tidak cocok', fail_res.text)

    def test_create_cert_does_not_add_to_users_table(self):
        """
        Creating a certificate must NOT create a public user in the database
        users table.
        """
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        # Check create cert form renders
        create_page = admin_app.get('/admin/create-cert', status=200)
        self.assertIn('Buat Sertifikat OpenVPN', create_page.text)

        # Make sure testclient99 does not exist in DB
        user_before = UserService.by_user_name(
            'testclient99', db_session=self.dbsession)
        self.assertIsNone(user_before)

        # Submit create cert form
        # (even if build-client-cert fails or succeeds in test environment, DB
        # must remain untouched)
        admin_app.post('/admin/create-cert', {
            'username': 'testclient99',
            'password': 'testpassword99',
        }, status=200)

        # Verify testclient99 was NOT added to users table in database
        fresh_db = self.session_factory()
        try:
            user_after = UserService.by_user_name(
                'testclient99', db_session=fresh_db)
            self.assertIsNone(user_after)
        finally:
            fresh_db.close()

    def test_create_cert_validation_username_and_password(self):
        """
        Test create cert validations:
        - Username only lowercase, digits, and minus.
        - Username cannot already exist in Linux (/etc/passwd).
        - Password must be at least 8 characters.
        """
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        # 1. Invalid username with underscore
        res_us = admin_app.post('/admin/create-cert', {
            'username': 'client_user',
            'password': 'password123',
        }, status=200)
        self.assertIn(
            'Username hanya boleh berisi huruf kecil, angka, '
            'dan karakter minus', res_us.text)

        # 2. Invalid username with dot
        res_dot = admin_app.post(
            '/admin/create-cert', {
                'username': 'client.user',
                'password': 'password123',
            }, status=200)
        self.assertIn(
            'Username hanya boleh berisi huruf kecil, angka, '
            'dan karakter minus', res_dot.text)

        # 3. Existing Linux user (e.g. root)
        res_root = admin_app.post('/admin/create-cert', {
            'username': 'root',
            'password': 'password123',
        }, status=200)
        self.assertIn(
            'sudah terdaftar di sistem Linux (/etc/passwd)', res_root.text)

        # 4. Short password (< 8 chars)
        res_short = admin_app.post('/admin/create-cert', {
            'username': 'valid-client-01',
            'password': 'short77',
        }, status=200)
        self.assertIn('Password minimal 8 karakter', res_short.text)

    def test_create_cert_proxy_checkbox(self):
        """Test proxy checkbox in create cert form and command generation."""
        from unittest.mock import patch

        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        orig_setting = self.app.registry.settings.get('openvpn.no_more_proxy')
        self.app.registry.settings['openvpn.no_more_proxy'] = False
        try:
            # 1. Page renders checkbox
            page = admin_app.get('/admin/create-cert', status=200)
            self.assertIn('Boleh akses proxy', page.text)
            self.assertIn('name="proxy"', page.text)

            # 2. Submit with proxy checked
            with patch('webmin_openvpn.views.admin.run_system_command') \
                 as mock_run, \
                 patch('webmin_openvpn.views.admin.set_proxy_user') \
                 as mock_set:
                mock_run.return_value = (0, "Success")
                admin_app.post('/admin/create-cert', {
                    'username': 'proxyclient',
                    'password': 'password123',
                    'proxy': '1',
                }, status=200)

                mock_run.assert_called_once()
                cmd_args = mock_run.call_args[0][0]
                self.assertEqual(cmd_args[1], 'proxyclient')
                self.assertIn('proxy', cmd_args)
                self.assertEqual(
                    cmd_args, [
                        '/usr/local/bin/build-client-cert', 'proxyclient',
                        'proxy', 'login', 'adduser', 'pass=password123'])
                # Verify set_proxy_user called with proxyclient
                mock_set.assert_called_once()
                self.assertEqual(mock_set.call_args[0][0], 'proxyclient')

            # 3. Submit without proxy checked
            with patch('webmin_openvpn.views.admin.run_system_command') \
                 as mock_run, \
                 patch('webmin_openvpn.views.admin.set_proxy_user') \
                 as mock_set:
                mock_run.return_value = (0, "Success")
                admin_app.post('/admin/create-cert', {
                    'username': 'noproxyclient',
                    'password': 'password123',
                }, status=200)

                mock_run.assert_called_once()
                cmd_args = mock_run.call_args[0][0]
                self.assertEqual(cmd_args[1], 'noproxyclient')
                self.assertNotIn('proxy', cmd_args)
                self.assertEqual(
                    cmd_args, [
                        '/usr/local/bin/build-client-cert', 'noproxyclient',
                        'login', 'adduser', 'pass=password123'])
                # Verify set_proxy_user was NOT called
                mock_set.assert_not_called()
        finally:
            self.app.registry.settings['openvpn.no_more_proxy'] = orig_setting

    def test_proxy_user_helpers(self):
        """Test get_proxy_user and set_proxy_user helper functions."""
        from unittest.mock import patch
        from webmin_openvpn.utils import get_proxy_user, set_proxy_user

        tmp_proxy = os.path.join(self.test_client_dir, 'helpers_proxy.txt')
        # None initially
        self.assertIsNone(get_proxy_user(tmp_proxy))

        # Test set_proxy_user saves to proxy.txt and executes firewall without
        # arguments
        with patch('webmin_openvpn.utils.run_system_command') as mock_cmd:
            mock_cmd.return_value = (0, "Success")
            # 1. Pilihan 1: username only
            res1 = set_proxy_user('karyoto', proxy_file=tmp_proxy)
            self.assertTrue(res1)
            with open(tmp_proxy, 'r') as f:
                self.assertEqual(f.read().strip(), 'karyoto')
            mock_cmd.assert_called_with(['/usr/local/bin/firewall'])

            res2 = set_proxy_user('husein', proxy_file=tmp_proxy)
            self.assertTrue(res2)
            with open(tmp_proxy, 'r') as f:
                self.assertEqual(f.read().strip(), 'husein')
            mock_cmd.assert_called_with(['/usr/local/bin/firewall'])

            # 2. Pilihan 2: username with ports
            res3 = set_proxy_user(
                'sugiana', ports='7070,6543', proxy_file=tmp_proxy)
            self.assertTrue(res3)
            with open(tmp_proxy, 'r') as f:
                self.assertEqual(f.read().strip(), 'sugiana:7070,6543')
            mock_cmd.assert_called_with(['/usr/local/bin/firewall'])

    def test_edit_and_change_password_min_length(self):
        """Test edit user password and change own password min 8 characters
        requirement."""
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        # 1. Edit user password < 8 chars
        res_edit = admin_app.post('/admin/users/sampleuser/password', {
            'new_password': '1234567',
            'confirm_password': '1234567',
        }, status=200)
        self.assertIn('Password minimal 8 karakter', res_edit.text)

        # 2. Admin change own password < 8 chars
        res_own = admin_app.post('/admin/change-password', {
            'current_password': 'admin',
            'new_password': '1234567',
            'confirm_password': '1234567',
        }, status=200)
        self.assertIn('Password baru minimal 8 karakter', res_own.text)

    def test_admin_system_stats_api(self):
        """Test /admin/api/system-stats returns JSON metrics for htop
        monitor."""
        # Anonymous should redirect to login
        res_anon = self.testapp.get('/admin/api/system-stats', status=302)
        self.assertIn('/login', res_anon.location)

        # Admin access returns 200 with JSON payload
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        res = admin_app.get('/admin/api/system-stats', status=200)
        self.assertEqual(res.content_type, 'application/json')
        data = res.json

        self.assertIn('cpu', data)
        self.assertIn('percent', data['cpu'])
        self.assertIn('ram', data)
        self.assertIn('percent', data['ram'])
        self.assertIn('swap', data)
        self.assertIn('percent', data['swap'])
        self.assertIn('disk', data)
        self.assertIn('percent', data['disk'])
        self.assertIn('network', data)
        self.assertIn('rx_speed_str', data['network'])
        self.assertIn('tx_speed_str', data['network'])

        # Dashboard page contains htop monitor elements
        dash_page = admin_app.get('/admin', status=200)
        self.assertIn('SYSTEM MONITOR [htop]', dash_page.text)
        self.assertIn('LIVE 1s', dash_page.text)
        self.assertIn('bar-cpu', dash_page.text)
        self.assertIn('bar-ram', dash_page.text)
        self.assertIn('bar-swap', dash_page.text)
        self.assertIn('bar-disk', dash_page.text)
        self.assertIn('bar-rx', dash_page.text)
        self.assertIn('bar-tx', dash_page.text)

    def test_admin_change_own_password(self):
        """Admin can change own password with >= 8 characters and revert
        back."""
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        res_change = admin_app.post('/admin/change-password', {
            'current_password': 'admin',
            'new_password': 'newadminpass88',
            'confirm_password': 'newadminpass88',
        }, status=302)
        self.assertIn('/admin', res_change.location)

        # Verify password in DB
        fresh_db = self.session_factory()
        try:
            admin_u = UserService.by_user_name('admin', db_session=fresh_db)
            self.assertTrue(admin_u.check_password('newadminpass88'))
            # Revert back
            admin_u.set_password('admin')
            fresh_db.commit()
        finally:
            fresh_db.close()

    def test_admin_users_has_hapus_button(self):
        """Daftar Pengguna table must have 'Hapus' button next to 'Ubah
        Password'."""
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        res = admin_app.get('/admin/users', status=200)
        self.assertIn('Ubah Password', res.text)
        self.assertIn('Hapus', res.text)
        self.assertIn('/admin/users/sampleuser/revoke', res.text)

    def test_admin_revoke_user_get_and_post_validation(self):
        """Test GET and validation failure for revoke confirmation form."""
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        # 1. GET revoke confirmation page
        get_res = admin_app.get('/admin/users/sampleuser/revoke', status=200)
        self.assertIn('Konfirmasi Hapus User', get_res.text)
        self.assertIn('Silakan hapus sampleuser', get_res.text)
        self.assertIn('Lanjut', get_res.text)
        self.assertIn('Tidak jadi', get_res.text)

        # 2. POST with wrong confirmation text
        fail_res = admin_app.post('/admin/users/sampleuser/revoke', {
            'confirm_text': 'hapus saja',
        }, status=200)
        self.assertIn('Kalimat konfirmasi belum sesuai', fail_res.text)
        self.assertIn('Silakan hapus sampleuser', fail_res.text)

        # 3. POST with cancel action
        cancel_res = admin_app.post('/admin/users/sampleuser/revoke', {
            'action': 'cancel',
        }, status=302)
        self.assertIn('/admin/users', cancel_res.location)

    def test_admin_revoke_user_post_success(self):
        """Test successful execution of revoke user command and tgz removal."""
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        self.assertTrue(os.path.exists(self.test_proxy_file))
        with patch('webmin_openvpn.views.admin.revoke_user') as mock_revoke:
            mock_revoke.return_value = (True, 'Revoked successfully')
            res = admin_app.post('/admin/users/sampleuser/revoke', {
                'confirm_text': 'Silakan hapus sampleuser',
            }, status=302)
            self.assertIn('/admin/users', res.location)
            mock_revoke.assert_called_once()
            self.assertEqual(mock_revoke.call_args[0][0], 'sampleuser')

        followed = res.follow(status=200)
        self.assertIn('User "sampleuser" berhasil dihapus.', followed.text)
        # Proxy file harus terhapus karena user di proxy.txt adalah sampleuser
        self.assertFalse(os.path.exists(self.test_proxy_file))

    def test_admin_revoke_user_keeps_proxy_file_for_different_user(self):
        """When proxy.txt has a different user, revoking sampleuser must keep
        proxy.txt intact."""
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        # Set proxy file to a different user
        with open(self.test_proxy_file, 'w') as f:
            f.write("otheruser:80,443\n")

        with patch('webmin_openvpn.views.admin.revoke_user') as mock_revoke:
            mock_revoke.return_value = (True, 'Revoked successfully')
            res = admin_app.post('/admin/users/sampleuser/revoke', {
                'confirm_text': 'Silakan hapus sampleuser',
            }, status=302)
            self.assertIn('/admin/users', res.location)

        self.assertTrue(os.path.exists(self.test_proxy_file))
        with open(self.test_proxy_file, 'r') as f:
            content = f.read()
        self.assertEqual(content.strip(), "otheruser:80,443")

    def test_admin_revoke_user_with_ports_in_proxy_file(self):
        """When proxy.txt has 'sampleuser:8080,9000', revoking sampleuser must
        delete proxy.txt."""
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        with open(self.test_proxy_file, 'w') as f:
            f.write("sampleuser:8080,9000\n")

        with patch('webmin_openvpn.views.admin.revoke_user') as mock_revoke:
            mock_revoke.return_value = (True, 'Revoked successfully')
            res = admin_app.post('/admin/users/sampleuser/revoke', {
                'confirm_text': 'Silakan hapus sampleuser',
            }, status=302)
            self.assertIn('/admin/users', res.location)

        self.assertFalse(os.path.exists(self.test_proxy_file))

    def test_revoke_user_utils(self):
        """Test revoke_user utility function executing command and deleting
        tgz."""
        from webmin_openvpn.utils import revoke_user

        with patch('webmin_openvpn.utils.run_system_command') as mock_run, \
             patch('os.path.exists') as mock_exists, \
             patch('os.remove') as mock_remove:
            mock_run.return_value = (0, 'OK')
            mock_exists.return_value = True

            success, out = revoke_user(
                'testclient99', revoke_cmd='/usr/local/bin/revoke-user',
                client_dir='/tmp')
            self.assertTrue(success)
            mock_run.assert_called_once_with([
                '/usr/local/bin/revoke-user', 'testclient99'])
            mock_remove.assert_called_once_with('/tmp/testclient99.tgz')

    def test_is_no_more_proxy_utils(self):
        """Test is_no_more_proxy helper for various settings values."""
        from webmin_openvpn.utils import is_no_more_proxy, is_proxy_file_exists

        # Default is True if not set
        self.assertTrue(is_no_more_proxy({}))
        # Explicit true strings
        self.assertTrue(is_no_more_proxy({'openvpn.no_more_proxy': 'true'}))
        self.assertTrue(is_no_more_proxy({'openvpn.no_more_proxy': 'True'}))
        self.assertTrue(is_no_more_proxy({'openvpn.no_more_proxy': '1'}))
        self.assertTrue(is_no_more_proxy({'openvpn.no_more_proxy': 'yes'}))
        self.assertTrue(is_no_more_proxy({'openvpn.no_more_proxy': True}))
        # Explicit false strings
        self.assertFalse(is_no_more_proxy({'openvpn.no_more_proxy': 'false'}))
        self.assertFalse(is_no_more_proxy({'openvpn.no_more_proxy': 'False'}))
        self.assertFalse(is_no_more_proxy({'openvpn.no_more_proxy': '0'}))
        self.assertFalse(is_no_more_proxy({'openvpn.no_more_proxy': 'no'}))
        self.assertFalse(is_no_more_proxy({'openvpn.no_more_proxy': False}))

        # Test is_proxy_file_exists
        self.assertTrue(is_proxy_file_exists(self.test_proxy_file))
        self.assertFalse(is_proxy_file_exists('/path/to/nonexistent/file.txt'))

    def test_no_more_proxy_true_with_proxy_file(self):
        """When proxy.txt exists and openvpn.no_more_proxy=true:
        - Proxy option in create-cert form is hidden.
        - Proxy button in users list is hidden.
        - Proxy badge is displayed next to proxy user's username.
        - Direct call to /admin/users/{u}/proxy is blocked.
        """
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        orig_setting = self.app.registry.settings.get('openvpn.no_more_proxy')
        self.app.registry.settings['openvpn.no_more_proxy'] = 'true'
        try:
            # 1. create-cert page: checkbox proxy is hidden
            cert_page = admin_app.get('/admin/create-cert', status=200)
            self.assertNotIn('Boleh akses proxy', cert_page.text)
            self.assertNotIn('name="proxy"', cert_page.text)

            # 2. users page: Proxy button in action column is hidden
            users_page = admin_app.get('/admin/users', status=200)
            self.assertNotIn('/admin/users/sampleuser/proxy', users_page.text)
            # Proxy badge next to username is present for proxy user
            # (sampleuser)
            self.assertIn('border-warning-subtle', users_page.text)
            self.assertIn('bi-shield-shaded me-1"></i>Proxy', users_page.text)
            self.assertIn('sampleuser', users_page.text)

            # 3. Direct access to set proxy route is blocked
            set_res = admin_app.get(
                '/admin/users/sampleuser/proxy', status=302)
            self.assertIn('/admin/users', set_res.location)
            followed = set_res.follow(status=200)
            self.assertIn('Opsi proxy dinonaktifkan', followed.text)
        finally:
            self.app.registry.settings['openvpn.no_more_proxy'] = orig_setting

    def test_no_more_proxy_false_with_proxy_file(self):
        """When proxy.txt exists and openvpn.no_more_proxy=false:
        - Proxy option in create-cert form is visible.
        - Proxy button in users list is visible.
        - Badge next to username is not displayed (represented by button).
        """
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        orig_setting = self.app.registry.settings.get('openvpn.no_more_proxy')
        self.app.registry.settings['openvpn.no_more_proxy'] = 'false'
        try:
            # 1. create-cert page: checkbox proxy is visible
            cert_page = admin_app.get('/admin/create-cert', status=200)
            self.assertIn('Boleh akses proxy', cert_page.text)
            self.assertIn('name="proxy"', cert_page.text)

            # 2. users page: Proxy button in action column is visible
            users_page = admin_app.get('/admin/users', status=200)
            self.assertIn('/admin/users/sampleuser/proxy', users_page.text)
            self.assertNotIn('border-warning-subtle', users_page.text)
        finally:
            self.app.registry.settings['openvpn.no_more_proxy'] = orig_setting

    def test_proxy_option_visible_when_proxy_file_missing(self):
        """When proxy.txt does not exist (even if no_more_proxy=true):
        - Proxy option in create-cert form is visible.
        - Proxy button in users list is visible.
        """
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        orig_proxy = self.app.registry.settings.get('openvpn.proxy_file')
        orig_setting = self.app.registry.settings.get('openvpn.no_more_proxy')
        self.app.registry.settings['openvpn.proxy_file'] = \
            '/tmp/nonexistent_proxy_file_xyz.txt'
        self.app.registry.settings['openvpn.no_more_proxy'] = 'true'
        try:
            # 1. create-cert page: checkbox proxy is visible
            cert_page = admin_app.get('/admin/create-cert', status=200)
            self.assertIn('Boleh akses proxy', cert_page.text)
            self.assertIn('name="proxy"', cert_page.text)

            # 2. users page: Proxy button in action column is visible
            users_page = admin_app.get('/admin/users', status=200)
            self.assertIn('/admin/users/sampleuser/proxy', users_page.text)
        finally:
            self.app.registry.settings['openvpn.proxy_file'] = orig_proxy
            self.app.registry.settings['openvpn.no_more_proxy'] = orig_setting

    def test_2fa_utils(self):
        """Test 2FA TOTP helper functions."""
        from webmin_openvpn.utils import (
            generate_totp_secret,
            generate_totp_uri,
            generate_totp_qr_svg_base64,
            format_totp_secret,
        )

        secret = generate_totp_secret()
        self.assertIsInstance(secret, str)
        self.assertEqual(len(secret), 32)

        uri = generate_totp_uri(secret, 'admin', issuer='WebminOpenVPN')
        self.assertTrue(uri.startswith(
            'otpauth://totp/WebminOpenVPN:admin?secret='))
        self.assertIn('issuer=WebminOpenVPN', uri)

        svg_data = generate_totp_qr_svg_base64(secret, 'admin')
        self.assertTrue(svg_data.startswith('data:image/svg+xml;base64,'))

        formatted = format_totp_secret('JBSWY3DPEHPK3PXP')
        self.assertEqual(formatted, 'JBSW Y3DP EHPK 3PXP')

    def test_admin_2fa_settings_and_activation(self):
        """Test Admin 2FA settings page, enabling 2FA with TOTP, and disabling
        it."""
        import pyotp
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        # 1. GET 2FA settings page when not yet enabled
        get_res = admin_app.get('/admin/2fa', status=200)
        self.assertIn('Aktivasi Google Authenticator', get_res.text)
        self.assertIn('data:image/svg+xml;base64,', get_res.text)
        # Retrieve pending secret from manualKeyInput
        import re
        match = re.search(
            r'id="manualKeyInput"\s+value="([A-Z0-9]+)"', get_res.text)
        self.assertIsNotNone(match)
        pending_secret = match.group(1)

        # 2. Try enabling with invalid token
        fail_res = admin_app.post('/admin/2fa', {
            'action': 'enable',
            'token': '000000',
        }, status=200)
        self.assertIn(
            'Kode verifikasi tidak valid atau kedaluwarsa', fail_res.text)

        # 3. Enable with valid TOTP token
        totp = pyotp.TOTP(pending_secret)
        valid_token = totp.now()
        success_res = admin_app.post('/admin/2fa', {
            'action': 'enable',
            'token': valid_token,
        }, status=302)
        self.assertIn('/admin/2fa', success_res.location)

        followed = success_res.follow(status=200)
        self.assertIn('berhasil diaktifkan', followed.text)
        self.assertIn('2FA Sedang Aktif', followed.text)

        # Verify DB user has totp_secret
        fresh_db = self.session_factory()
        try:
            admin_u = UserService.by_user_name('admin', db_session=fresh_db)
            self.assertTrue(admin_u.has_2fa)
            self.assertEqual(admin_u.totp_secret, pending_secret)
        finally:
            fresh_db.close()

        # 4. Try disabling with wrong password
        fail_dis = admin_app.post('/admin/2fa', {
            'action': 'disable',
            'password': 'wrongpassword',
        }, status=200)
        self.assertIn('Kata sandi yang Anda masukkan salah', fail_dis.text)

        # 5. Disable with correct password
        ok_dis = admin_app.post('/admin/2fa', {
            'action': 'disable',
            'password': 'admin',
        }, status=302)
        self.assertIn('/admin/2fa', ok_dis.location)

        followed_dis = ok_dis.follow(status=200)
        self.assertIn(
            'Two-Factor Authentication berhasil dinonaktifkan',
            followed_dis.text)
        self.assertIn('Aktivasi Google Authenticator', followed_dis.text)

        fresh_db2 = self.session_factory()
        try:
            admin_u2 = UserService.by_user_name('admin', db_session=fresh_db2)
            self.assertFalse(admin_u2.has_2fa)
            self.assertIsNone(admin_u2.totp_secret)
        finally:
            fresh_db2.close()

    def test_login_flow_with_and_without_2fa(self):
        """Test login flow transitions between standard 1-step and 2-step
        TOTP."""
        import pyotp
        app = webtest.TestApp(self.app)

        # 1. Login without 2FA -> direct login (302 -> /admin)
        res1 = app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)
        self.assertIn('/admin', res1.location)
        app.get('/logout', status=302)

        # 2. Activate 2FA on admin user
        secret = pyotp.random_base32()
        fresh_db = self.session_factory()
        try:
            admin_u = UserService.by_user_name('admin', db_session=fresh_db)
            admin_u.totp_secret = secret
            fresh_db.commit()
        finally:
            fresh_db.close()

        try:
            # 3. Step 1: POST /login with username & password
            res_step1 = app.post(
                '/login', {'username': 'admin', 'password': 'admin'},
                status=302)
            # Should redirect to /login/2fa, NOT /admin
            self.assertIn('/login/2fa', res_step1.location)

            # 4. GET /login/2fa displays verification page
            page_2fa = app.get('/login/2fa', status=200)
            self.assertIn('Verifikasi 2FA', page_2fa.text)
            self.assertIn('Google Authenticator', page_2fa.text)
            self.assertIn('name="token"', page_2fa.text)

            # 5. POST /login/2fa with invalid token
            fail_2fa = app.post('/login/2fa', {'token': '123123'}, status=200)
            self.assertIn(
                'Kode verifikasi tidak valid atau telah kedaluwarsa',
                fail_2fa.text)

            # 6. POST /login/2fa with action=cancel redirects back to /login
            cancel_2fa = app.post(
                '/login/2fa', {'action': 'cancel'}, status=302)
            self.assertIn('/login', cancel_2fa.location)

            # Repeat step 1
            app.post(
                '/login', {'username': 'admin', 'password': 'admin'},
                status=302)

            # 7. POST /login/2fa with valid TOTP code
            valid_code = pyotp.TOTP(secret).now()
            res_step2 = app.post(
                '/login/2fa', {'token': valid_code}, status=302)
            self.assertIn('/admin', res_step2.location)

            # Now authenticated, accessing dashboard succeeds
            dash = res_step2.follow(status=200)
            self.assertIn('SYSTEM MONITOR', dash.text)

        finally:
            # Clean up: remove 2FA secret from DB
            clean_db = self.session_factory()
            try:
                admin_clean = UserService.by_user_name(
                    'admin', db_session=clean_db)
                admin_clean.totp_secret = None
                clean_db.commit()
            finally:
                clean_db.close()

    def test_admin_users_status_column(self):
        """Test status column (ON / OFF + time + red background for OFF) in
        admin users list."""
        self.testapp.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        expected_time_on = None
        db = self.session_factory()
        try:
            vpn = db.query(VPN).filter_by(nama='sampleuser').first()
            if not vpn:
                vpn = VPN(nama='sampleuser', ip='10.8.41.99')
                db.add(vpn)
            else:
                vpn.ip = '10.8.41.99'
            vpn.terhubung = True
            vpn.ip_sumber = '198.51.100.42'
            vpn.perubahan = datetime(2026, 10, 19, 14, 30, 0)
            db.commit()
            db.refresh(vpn)
            expected_time_on = vpn.perubahan.strftime('%d/%m/%Y %H:%M:%S')
        finally:
            db.close()

        res_on = self.testapp.get('/admin/users', status=200)
        self.assertIn('<th>Status</th>', res_on.text)
        self.assertIn('>ON</span>', res_on.text)
        self.assertIn(expected_time_on, res_on.text)
        self.assertIn('198.51.100.42', res_on.text)

        # 2. When disconnected (OFF with red background)
        expected_time_off = None
        db = self.session_factory()
        try:
            vpn = db.query(VPN).filter_by(nama='sampleuser').first()
            vpn.terhubung = False
            vpn.perubahan = datetime(2026, 10, 19, 15, 45, 12)
            db.commit()
            db.refresh(vpn)
            expected_time_off = vpn.perubahan.strftime('%d/%m/%Y %H:%M:%S')
        finally:
            db.close()

        res_off = self.testapp.get('/admin/users', status=200)
        self.assertIn('badge bg-danger', res_off.text)
        self.assertIn(f'OFF {expected_time_off}', res_off.text)

        # 3. Clean up sampleuser VPN record
        db = self.session_factory()
        try:
            vpn = db.query(VPN).filter_by(nama='sampleuser').first()
            if vpn:
                db.delete(vpn)
                db.commit()
        finally:
            db.close()

    def test_reverse_proxy_ports_utils(self):
        """Test utils functions for get_proxy_info, get_proxy_user, and
        get_proxy_ports."""
        from webmin_openvpn.utils import (
            get_proxy_info,
            get_proxy_user,
            get_proxy_ports,
        )

        test_file = os.path.join(self.test_client_dir, 'utils_proxy_test.txt')
        if os.path.exists(test_file):
            os.remove(test_file)

        # 1. Non-existent file returns (None, None)
        self.assertEqual(get_proxy_info(test_file), (None, None))
        self.assertIsNone(get_proxy_user(test_file))
        self.assertIsNone(get_proxy_ports(test_file))

        # 2. File with username only
        with open(test_file, 'w') as f:
            f.write("sugiana\n")
        self.assertEqual(get_proxy_info(test_file), ('sugiana', None))
        self.assertEqual(get_proxy_user(test_file), 'sugiana')
        self.assertIsNone(get_proxy_ports(test_file))

        # 3. File with username:ports
        with open(test_file, 'w') as f:
            f.write("sugiana:7070,6543\n")
        self.assertEqual(get_proxy_info(test_file), ('sugiana', '7070,6543'))
        self.assertEqual(get_proxy_user(test_file), 'sugiana')
        self.assertEqual(get_proxy_ports(test_file), '7070,6543')

    def test_admin_reverse_proxy_ports_flow(self):
        """Test admin reverse proxy ports modal, save custom ports, and save
        all ports."""
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        # 1. Verify /admin/users renders the modal and proxy badge
        users_res = admin_app.get('/admin/users', status=200)
        self.assertIn('data-bs-target="#proxyPortsModal"', users_res.text)
        self.assertIn('proxyPortsModalLabel', users_res.text)
        self.assertIn(
            'Forward semua port kecuali 22, 80, 443, 1194', users_res.text)
        self.assertIn('Hanya forward port tertentu', users_res.text)
        self.assertIn('id="reverseProxyPortsInput"', users_res.text)

        # 2. Save custom ports: 6969,8081 (Pilihan 2)
        post_custom = admin_app.post(
            '/admin/users/proxy-ports',
            {
                'username': 'sampleuser',
                'proxy_port_mode': 'custom',
                'reverse_proxy_ports': '6969,8081',
            },
            status=302,
        )
        self.assertIn('/admin/users', post_custom.location)
        users_after_custom = post_custom.follow(status=200)
        self.assertIn('6969,8081', users_after_custom.text)
        self.assertIn(
            'font-monospace badge-proxy-clickable',
            users_after_custom.text)
        with open(self.test_proxy_file, 'r') as f:
            self.assertEqual(f.read().strip(), 'sampleuser:6969,8081')

        # 3. Save all ports (Pilihan 1): saves sampleuser to proxy.txt and runs
        # firewall
        post_all = admin_app.post(
            '/admin/users/proxy-ports',
            {
                'username': 'sampleuser',
                'proxy_port_mode': 'all',
                'reverse_proxy_ports': '',
            },
            status=302,
        )
        self.assertIn('/admin/users', post_all.location)
        users_after_all = post_all.follow(status=200)
        self.assertIn(
            'Pengaturan proxy untuk "sampleuser" berhasil disimpan',
            users_after_all.text)
        with open(self.test_proxy_file, 'r') as f:
            self.assertEqual(f.read().strip(), 'sampleuser')

        # 4. Validation: Empty ports for custom mode
        post_empty = admin_app.post(
            '/admin/users/proxy-ports',
            {
                'username': 'sampleuser',
                'proxy_port_mode': 'custom',
                'reverse_proxy_ports': '',
            },
            status=302,
        )
        res_empty = post_empty.follow(status=200)
        self.assertIn('Port tidak boleh kosong', res_empty.text)

        # 5. Validation: Invalid characters for custom mode
        post_invalid_chars = admin_app.post(
            '/admin/users/proxy-ports',
            {
                'username': 'sampleuser',
                'proxy_port_mode': 'custom',
                'reverse_proxy_ports': '6969,abc',
            },
            status=302,
        )
        res_invalid_chars = post_invalid_chars.follow(status=200)
        self.assertIn('Format port tidak valid', res_invalid_chars.text)

        # 6. Validation: Invalid port range
        post_invalid_range = admin_app.post(
            '/admin/users/proxy-ports',
            {
                'username': 'sampleuser',
                'proxy_port_mode': 'custom',
                'reverse_proxy_ports': '6969,70000',
            },
            status=302,
        )
        res_invalid_range = post_invalid_range.follow(status=200)
        self.assertIn('Nomor port tidak valid', res_invalid_range.text)

        # 7. GET request redirects to /admin/users
        get_res = admin_app.get('/admin/users/proxy-ports', status=302)
        self.assertIn('/admin/users', get_res.location)

    def test_firewall_top_nav_menu_and_change_password_removed(self):
        """Top nav menu must have 'Firewall' and remove 'Ubah Password' from
        top nav, while user dropdown list retains 'Ubah Password Saya'."""
        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        res = admin_app.get('/admin', status=200)
        # Top nav has Firewall link
        self.assertIn('href="http://localhost/admin/firewall"', res.text)
        self.assertIn('Firewall', res.text)
        # Top nav does not have the removed top link
        self.assertNotIn(
            '<i class="bi bi-key me-1"></i> Ubah Password', res.text)
        # User dropdown still has Ubah Password Saya
        self.assertIn('Ubah Password Saya', res.text)
        self.assertIn(
            'href="http://localhost/admin/change-password"', res.text)

    def test_admin_firewall_get_and_post_flows(self):
        """Test GET and POST firewall rules (Blacklist & Whitelist) including
        file creation, file removal when empty, and firewall script
        execution."""
        from webmin_openvpn.utils import validate_ip_list

        # Test utils validation
        valid, ips, err = validate_ip_list("192.168.1.1\n\n10.8.0.5\n")
        self.assertTrue(valid)
        self.assertEqual(ips, ['192.168.1.1', '10.8.0.5'])

        valid_empty, empty_ips, _ = validate_ip_list("   \n\n  ")
        self.assertTrue(valid_empty)
        self.assertEqual(empty_ips, [])

        invalid, _, err_msg = validate_ip_list("192.168.1.1\n999.0.0.1")
        self.assertFalse(invalid)
        self.assertIn('bukan alamat IPv4 yang valid', err_msg)

        admin_app = webtest.TestApp(self.app)
        admin_app.post(
            '/login', {'username': 'admin', 'password': 'admin'}, status=302)

        # 1. GET /admin/firewall
        fw_page = admin_app.get('/admin/firewall', status=200)
        self.assertIn('Pengaturan Firewall', fw_page.text)
        self.assertIn('Blacklist', fw_page.text)
        self.assertIn('Whitelist', fw_page.text)

        # 2. POST with valid Blacklist and Whitelist
        post_res = admin_app.post('/admin/firewall', {
            'blacklist': "10.0.0.99\n192.168.1.200",
            'whitelist': "1.1.1.1\n\n8.8.8.8",
        }, status=200)
        self.assertIn(
            'Pengaturan firewall berhasil disimpan dan diterapkan',
            post_res.text)
        self.assertIn('Firewall dummy output: rules applied', post_res.text)

        # Verify files were created with correct IPs
        self.assertTrue(os.path.exists(self.test_blacklist_file))
        self.assertTrue(os.path.exists(self.test_whitelist_file))
        with open(self.test_blacklist_file, 'r') as f:
            self.assertEqual(f.read(), "10.0.0.99\n192.168.1.200\n")
        with open(self.test_whitelist_file, 'r') as f:
            self.assertEqual(f.read(), "1.1.1.1\n8.8.8.8\n")

        # 3. POST with empty Blacklist and empty Whitelist -> files must be
        # removed
        post_empty = admin_app.post('/admin/firewall', {
            'blacklist': "\n   \n",
            'whitelist': "",
        }, status=200)
        self.assertIn(
            'Pengaturan firewall berhasil disimpan dan diterapkan',
            post_empty.text)
        self.assertFalse(os.path.exists(self.test_blacklist_file))
        self.assertFalse(os.path.exists(self.test_whitelist_file))

        # 4. POST with invalid IPv4 in Blacklist
        post_invalid_b = admin_app.post('/admin/firewall', {
            'blacklist': "not-an-ip",
            'whitelist': "",
        }, status=200)
        self.assertIn('bukan alamat IPv4 yang valid', post_invalid_b.text)
        self.assertFalse(os.path.exists(self.test_blacklist_file))

        # 5. POST with invalid IPv4 in Whitelist
        post_invalid_w = admin_app.post('/admin/firewall', {
            'blacklist': "",
            'whitelist': "10.0.0.1/24",
        }, status=200)
        self.assertIn('bukan alamat IPv4 yang valid', post_invalid_w.text)
        self.assertFalse(
            os.path.exists(self.test_whitelist_file))
