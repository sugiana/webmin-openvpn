import sys
import re
import argparse
from datetime import datetime
from subprocess import (
    Popen,
    PIPE,
    )
from pyramid.paster import bootstrap, setup_logging
from sqlalchemy import engine_from_config
from ..models.network import VPN


REGEX_ON = re.compile(
    r'^([\d]*-[\d]*-[\d]*T[\d]*:[\d]*:[\d]*[+-][\d]*:[\d]*) (.*): '
    r'(.*)/(.*) MULTI_sva: pool returned IPv4=(.*), (.*)')
REGEX_OFF = re.compile(
    r'^([\d]*-[\d]*-[\d]*T[\d]*:[\d]*:[\d]*[+-][\d]*:[\d]*) (.*): '
    r'(.*)/(.*) Connection reset, (.*)')

status = dict()
user_ip = dict()


def show(dt, user, new_status):
    if user in user_ip:
        ip = user_ip[user]
        print(dt, user, new_status, ip)
    else:
        print(dt, user, new_status)


def read_once():
    cmd = ['journalctl', '-u', 'openvpn@server', '--output=short-iso']
    print(' '.join(cmd))
    f = Popen(cmd, stdout=PIPE, stderr=PIPE, text=True, bufsize=1)
    for line in f.stdout:
        line = line.rstrip()
        match = REGEX_ON.search(line)
        if match:
            new_status = True
            ip = match.group(5)
        else:
            match = REGEX_OFF.search(line)
            if match:
                new_status = False
            else:
                continue
        dt = match.group(1)
        user = match.group(3)
        dt = datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S%z')
        if new_status:
            if ip not in user_ip:
                user_ip[user] = ip
        show(dt, user, new_status)
        if user not in status:
            status[user] = dict(status=new_status, dt=dt)
            continue
        old_status = status[user]['status']
        if old_status == new_status:
            continue
        status[user] = dict(status=new_status, dt=dt)


def read_forever():
    cmd = ['journalctl', '-u', 'openvpn@server', '--output=short-iso', '-f']
    print(' '.join(cmd))
    f = Popen(cmd, stdout=PIPE, stderr=PIPE, text=True, bufsize=1)
    for line in f.stdout:
        line = line.rstrip()
        match = REGEX_ON.search(line)
        if match:
            new_status = True
            ip = match.group(5)
        else:
            match = REGEX_OFF.search(line)
            if match:
                new_status = False
            else:
                continue
        dt = match.group(1)
        user = match.group(3)
        dt = datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S%z')
        if new_status:
            if ip not in user_ip:
                user_ip[user] = ip
        if user not in status:
            status[user] = dict(status=new_status, dt=dt)
            continue
        last_dt = status[user]['dt']
        if dt <= last_dt:
            continue
        status[user] = dict(status=new_status, dt=dt)
        show(dt, user, new_status)


def save(env, nama: str, terhubung: bool, perubahan: datetime, ip: str):
    with env['request'].tm:
        dbsession = env['request'].dbsession
        q = dbsession.query(VPN).filter_by(ip=ip)
        row = q.first()
        if row and row.nama != nama:
            # Hapus IP ganda
            q.delete()
        q = dbsession.query(VPN).filter_by(nama=nama)
        row = q.first()
        if row:
            if row.perubahan > perubahan:
                return
            if row.terhubung == terhubung:
                return
            print(nama, ip, f'{row.terhubung} -> {terhubung}')
        else:
            print(nama, ip, terhubung)
            row = VPN(nama=nama, ip=ip)
        row.terhubung = terhubung
        row.perubahan = perubahan
        dbsession.add(row)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description='Initialize OpenVPN Web Management Database'
    )
    parser.add_argument(
        'config_uri',
        help='Configuration file, e.g., development.ini',
    )
    return parser.parse_args(argv[1:])


def main(argv=sys.argv):
    args = parse_args(argv)
    setup_logging(args.config_uri)
    env = bootstrap(args.config_uri)
    status = dict()
    user_ip = dict()
    # Baca log
    cmd = ['journalctl', '-u', 'openvpn@server', '--output=short-iso']
    print(' '.join(cmd))
    f = Popen(cmd, stdout=PIPE, stderr=PIPE, text=True, bufsize=1)
    for line in f.stdout:
        line = line.rstrip()
        match = REGEX_ON.search(line)
        if match:
            new_status = True
            ip = match.group(5)
        else:
            match = REGEX_OFF.search(line)
            if match:
                new_status = False
            else:
                continue
        dt = match.group(1)
        user = match.group(3)
        dt = datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S%z')
        if new_status:
            if ip not in user_ip:
                user_ip[user] = ip
        if user not in status:
            status[user] = dict(status=new_status, dt=dt)
            continue
        old_status = status[user]['status']
        if old_status == new_status:
            continue
        status[user] = dict(status=new_status, dt=dt)
    for user, v in status.items():
        if user not in user_ip:
            continue
        ip = user_ip[user]
        save(env, user, v['status'], v['dt'], ip)
    # Pantau perubahan log
    cmd += ['-f']
    print(' '.join(cmd))
    f = Popen(cmd, stdout=PIPE, stderr=PIPE, text=True, bufsize=1)
    for line in f.stdout:
        line = line.rstrip()
        match = REGEX_ON.search(line)
        if match:
            new_status = True
            ip = match.group(5)
        else:
            match = REGEX_OFF.search(line)
            if match:
                new_status = False
            else:
                continue
        dt = match.group(1)
        user = match.group(3)
        dt = datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S%z')
        if new_status:
            if ip not in user_ip:
                user_ip[user] = ip
        if user not in user_ip:
            continue
        ip = user_ip[user]
        save(env, user, new_status, dt, ip)
