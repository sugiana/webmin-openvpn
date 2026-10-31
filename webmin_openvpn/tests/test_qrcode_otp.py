import os
import tempfile
import unittest
from webmin_openvpn.scripts.qrcode_otp import parse_args, main
from webmin_openvpn.models import (
    get_engine,
    get_session_factory,
    UserService,
)
from pyramid.paster import get_appsettings


class TestQrcodeOtpScript(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ini_path = os.path.abspath('test.ini')
        settings = get_appsettings(cls.ini_path)
        cls.engine = get_engine(settings)
        cls.session_factory = get_session_factory(cls.engine)

    def setUp(self):
        self.dbsession = self.session_factory()
        admin = UserService.by_user_name('admin', db_session=self.dbsession)
        if admin:
            admin.totp_secret = None
            self.dbsession.commit()
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        self.dbsession.close()
        if os.path.exists(self.tmp_dir):
            import shutil
            shutil.rmtree(self.tmp_dir)

    def test_parse_args(self):
        args = parse_args(['qrcode_otp', 'test.ini', 'admin'])
        self.assertEqual(args.config_uri, 'test.ini')
        self.assertEqual(args.user_name, 'admin')
        self.assertIsNone(args.output)
        self.assertFalse(args.regenerate)

        args = parse_args([
            'qrcode_otp', 'test.ini', 'admin',
            '-o', 'custom.svg', '--regenerate', '--issuer', 'MyIssuer'
        ])
        self.assertEqual(args.output, 'custom.svg')
        self.assertTrue(args.regenerate)
        self.assertEqual(args.issuer, 'MyIssuer')

    def test_main_user_not_found(self):
        with self.assertRaises(SystemExit) as cm:
            main(['qrcode_otp', self.ini_path, 'non_existent_user_xyz'])
        self.assertEqual(cm.exception.code, 1)

    def test_main_generates_and_reuses_secret(self):
        output_svg = os.path.join(self.tmp_dir, 'qrcode_otp_admin.svg')
        # First run: admin has no totp_secret
        main(['qrcode_otp', self.ini_path, 'admin', '-o', output_svg])
        self.assertTrue(os.path.exists(output_svg))
        with open(output_svg, 'r') as f:
            content = f.read()
        self.assertIn('<svg', content)

        # Check DB
        dbsession = self.session_factory()
        admin = UserService.by_user_name('admin', db_session=dbsession)
        self.assertIsNotNone(admin.totp_secret)
        first_secret = admin.totp_secret
        dbsession.close()

        # Second run: should reuse existing secret
        main(['qrcode_otp', self.ini_path, 'admin', '-o', output_svg])
        dbsession2 = self.session_factory()
        admin2 = UserService.by_user_name('admin', db_session=dbsession2)
        self.assertEqual(admin2.totp_secret, first_secret)
        dbsession2.close()

        # Third run: with --regenerate
        main([
            'qrcode_otp', self.ini_path, 'admin', '-o', output_svg,
            '--regenerate'])
        dbsession3 = self.session_factory()
        admin3 = UserService.by_user_name('admin', db_session=dbsession3)
        self.assertNotEqual(admin3.totp_secret, first_secret)
        dbsession3.close()
