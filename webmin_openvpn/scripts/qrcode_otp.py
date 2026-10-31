import os
import sys
import argparse
from pyramid.paster import bootstrap, setup_logging
import qrcode
import qrcode.image.svg

try:
    from ..models.auth import UserService
    from ..utils import (
        generate_totp_secret,
        generate_totp_uri,
    )
except (ImportError, ValueError):
    from webmin_openvpn.models.auth import UserService
    from webmin_openvpn.utils import (
        generate_totp_secret,
        generate_totp_uri,
    )


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description='Generate QR code SVG for user TOTP secret'
    )
    parser.add_argument(
        'config_uri',
        help='Configuration file, e.g., development.ini',
    )
    parser.add_argument(
        'user_name',
        help='Username in users table',
    )
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='Output SVG file path (default: qrcode_otp_<user_name>.svg)',
    )
    parser.add_argument(
        '--issuer',
        default=None,
        help='Issuer name for TOTP (default: WebminOpenVPN)',
    )
    parser.add_argument(
        '--regenerate', '--new',
        action='store_true',
        dest='regenerate',
        help='Generate a new totp_secret if already set',
    )
    return parser.parse_args(argv[1:])


def main(argv=sys.argv):
    args = parse_args(argv)
    setup_logging(args.config_uri)
    env = bootstrap(args.config_uri)
    try:
        with env['request'].tm:
            dbsession = env['request'].dbsession
            user = UserService.by_user_name(
                    args.user_name, db_session=dbsession)
            if not user:
                print(
                    f"Error: User '{args.user_name}' tidak ditemukan.",
                    file=sys.stderr,
                )
                sys.exit(1)

            if not user.totp_secret or args.regenerate:
                user.totp_secret = generate_totp_secret()
                dbsession.add(user)
                dbsession.flush()
                print(
                    f"Dibuat secret baru untuk '{user.user_name}': "
                    f"{user.totp_secret}"
                )
            else:
                print(
                    "Menggunakan totp_secret yang ada untuk "
                    f"'{user.user_name}': "
                    f"{user.totp_secret}"
                )

            issuer = (
                args.issuer
                or env['registry'].settings.get('totp.issuer', 'WebminOpenVPN')
            )
            output_file = args.output or f"qrcode_otp_{user.user_name}.svg"
            output_dir = os.path.dirname(output_file)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            uri = generate_totp_uri(
                    user.totp_secret, user.user_name, issuer=issuer)
            img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
            img.save(output_file)
            print(f"QR code SVG berhasil disimpan ke: {output_file}")
    finally:
        closer = env.get('closer')
        if closer:
            closer()


if __name__ == '__main__':
    main()
