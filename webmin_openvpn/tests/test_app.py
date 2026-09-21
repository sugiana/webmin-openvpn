import os
import tempfile
import shutil
import unittest
import webtest
from pyramid.paster import get_appsettings
from webmin_openvpn import main
from webmin_openvpn.models import (
    get_engine,
    get_session_factory,
    User,
    UserService,
    )


class TestWebminOpenVPN(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ini_path = os.path.abspath('test.ini')
        settings = get_appsettings(ini_path)

        # Setup isolated temp client dir with a test cert
        cls.test_client_dir = tempfile.mkdtemp()
        settings['openvpn.client_dir'] = cls.test_client_dir
        dummy_cert_path = os.path.join(cls.test_client_dir, 'sampleuser.tgz')
        with open(dummy_cert_path, 'wb') as f:
            f.write(b'dummy gzip content for test')

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

    def tearDown(self):
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
        self.assertIn('sampleuser.tgz', users_page.text)

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
        self.assertIn('Konfirmasi password tidak cocok', fail_res.text)

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
