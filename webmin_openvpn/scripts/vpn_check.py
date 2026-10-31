import sys
import re
import argparse
from datetime import (
    datetime,
    timezone,
    )
from subprocess import (
    Popen,
    PIPE,
    )
from pyramid.paster import bootstrap, setup_logging
from sqlalchemy import engine_from_config
from ..utils import load_ipp_map
from ..models.network import VPN


REGEX_ON = re.compile(
    r'^([\d]*-[\d]*-[\d]*T[\d]*:[\d]*:[\d]*[+-][\d]*:[\d]*) (.*): '
    r'(.*)/(.*):(.*) MULTI: primary virtual IP for (.*)/(.*):(.*): (.*)')
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
            ip = match.group(9)
        else:
            match = REGEX_OFF.search(line)
            if not match:
                continue
            new_status = False
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
            ip = match.group(9)
        else:
            match = REGEX_OFF.search(line)
            if not match:
                continue
            new_status = False
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


def ping(ip: str) -> bool:
    cmd1 = ['ping', '-c1', '-w', '2', ip]
    cmd2 = ['grep', 'received']
    cmd3 = ['cut', '-f4', '-d', ' ']
    p1 = Popen(cmd1, stdout=PIPE)
    p2 = Popen(cmd2, stdin=p1.stdout, stdout=PIPE)
    p3 = Popen(cmd3, stdin=p2.stdout, stdout=PIPE)
    stdout, stderr = p3.communicate()
    n = stdout.decode('utf-8').rstrip()
    return n == '1'


def save(
        env, nama: str, terhubung: bool, perubahan: datetime, ip: str,
        ip_sumber: str = None):
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
        if ip_sumber:
            row.ip_sumber = ip_sumber
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
    user_ip = load_ipp_map()
    for user, ip in user_ip.items():
        new_status = ping(ip)
        dt = datetime.now(tz=timezone.utc)
        save(env, user, new_status, dt, ip)
    # Baca log
    cmd = ['journalctl', '-u', 'openvpn@server', '--output=short-iso']
    print(' '.join(cmd))
    f = Popen(cmd, stdout=PIPE, stderr=PIPE, text=True, bufsize=1)
    for line in f.stdout:
        line = line.rstrip()
        match = REGEX_ON.search(line)
        if match:
            new_status = True
            ip = match.group(9)
            ip_sumber = match.group(4)
        else:
            match = REGEX_OFF.search(line)
            if not match:
                continue
            new_status = False
            ip_sumber = None
        dt = match.group(1)
        user = match.group(3)
        dt = datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S%z')
        if new_status:
            if user not in user_ip:
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
        save(env, user, v['status'], v['dt'], ip, ip_sumber)
    # Pantau perubahan log
    cmd += ['-f']
    print(' '.join(cmd))
    f = Popen(cmd, stdout=PIPE, stderr=PIPE, text=True, bufsize=1)
    for line in f.stdout:
        line = line.rstrip()
        match = REGEX_ON.search(line)
        if match:
            new_status = True
            ip = match.group(9)
            ip_sumber = match.group(4)
        else:
            match = REGEX_OFF.search(line)
            if not match:
                continue
            new_status = False
            ip_sumber = None
        dt = match.group(1)
        user = match.group(3)
        dt = datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S%z')
        if new_status:
            if ip not in user_ip:
                user_ip[user] = ip
        if user not in user_ip:
            continue
        ip = user_ip[user]
        save(env, user, new_status, dt, ip, ip_sumber)
