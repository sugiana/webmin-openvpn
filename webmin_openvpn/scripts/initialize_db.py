import os
import sys
import argparse
import transaction
from pyramid.paster import bootstrap, setup_logging
from sqlalchemy import engine_from_config

from ..models.meta import Base
from ..models.auth import (
    User,
    Group,
    UserGroup,
    GroupPermission,
    UserService,
    GroupService,
)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description='Initialize OpenVPN Web Management Database'
    )
    parser.add_argument(
        'config_uri',
        help='Configuration file, e.g., development.ini',
    )
    parser.add_argument(
        '--admin-user',
        default='admin',
        help='Default admin username (default: admin)',
    )
    parser.add_argument(
        '--admin-pass',
        default='admin',
        help='Default admin password (default: admin)',
    )
    parser.add_argument(
        '--admin-email',
        default='admin@localhost',
        help='Default admin email (default: admin@localhost)',
    )
    return parser.parse_args(argv[1:])


def setup_models(
        dbsession, admin_user='admin', admin_pass='admin',
        admin_email='admin@localhost'):
    """
    Seed initial groups and admin user.
    """
    # 1. Create 'admin' group
    admin_group = GroupService.by_group_name('admin', db_session=dbsession)
    if not admin_group:
        admin_group = Group(
            group_name='admin', description='Administrator Group')
        dbsession.add(admin_group)
        dbsession.flush()
        print("Created group: admin")

    # 2. Create 'publik' group
    public_group = GroupService.by_group_name('publik', db_session=dbsession)
    if not public_group:
        public_group = Group(
            group_name='publik', description='Public / Client User Group')
        dbsession.add(public_group)
        dbsession.flush()
        print("Created group: publik")

    # 3. Create default admin user if not exists
    user = UserService.by_user_name(admin_user, db_session=dbsession)
    if not user:
        user = User(
            user_name=admin_user,
            email=admin_email,
            status=1,
        )
        user.set_password(admin_pass)
        dbsession.add(user)
        dbsession.flush()

        # Add admin user to admin group
        user_group = UserGroup(user_id=user.id, group_id=admin_group.id)
        dbsession.add(user_group)
        print(f"Created admin user: {admin_user} (password: {admin_pass})")
    else:
        # Ensure admin is in admin group
        if admin_group not in user.groups:
            user_group = UserGroup(user_id=user.id, group_id=admin_group.id)
            dbsession.add(user_group)
            print(f"Added existing user {admin_user} to admin group")


def main(argv=sys.argv):
    args = parse_args(argv)
    setup_logging(args.config_uri)
    env = bootstrap(args.config_uri)
    try:
        with env['request'].tm:
            dbsession = env['request'].dbsession
            engine = dbsession.bind
            print(f"Creating tables in database: {engine.url}")
            Base.metadata.create_all(engine)
            try:
                import sqlalchemy as sa
                with engine.connect() as conn:
                    conn.execute(sa.text(
                        "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
                        "totp_secret VARCHAR(64);"))
                    conn.commit()
            except Exception:
                pass
            try:
                import sqlalchemy as sa
                with engine.connect() as conn:
                    conn.execute(sa.text(
                        "ALTER TABLE openvpn ADD COLUMN IF NOT EXISTS "
                        "ip_sumber VARCHAR(15);"))
                    conn.commit()
            except Exception:
                pass
            setup_models(
                dbsession,
                admin_user=args.admin_user,
                admin_pass=args.admin_pass,
                admin_email=args.admin_email,
            )
            print("Creating firewall ipsets (whitelist & blacklist)...")
            setup_ipset()
            print("Database initialization complete!")
    except Exception as e:
        print(f"Error during initialization: {e}", file=sys.stderr)
        raise


def setup_ipset():
    """
    Pembuatan himpunan whitelist dan blacklist:
    ipset create whitelist hash:ip
    ipset create blacklist hash:ip
    """
    from ..utils import run_system_command

    for name in ['whitelist', 'blacklist']:
        print(f"Creating ipset: {name}")
        rc, out = run_system_command([
            'ipset', 'create', name, 'hash:ip', '-exist'])
        if rc != 0 and 'already exists' not in (out or ''):
            rc2, out2 = run_system_command([
                'ipset', 'create', name, 'hash:ip'])
            if rc2 != 0 and 'already exists' not in (out2 or ''):
                print(
                    f"Warning: Failed to create ipset {name}: {out2}",
                    file=sys.stderr)


if __name__ == '__main__':
    main()
