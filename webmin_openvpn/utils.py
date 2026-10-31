import os
import time
import pwd
import subprocess
import logging
import ipaddress
from datetime import datetime

logger = logging.getLogger(__name__)

# State tracking for CPU and Network delta rate calculations
_last_cpu_stat = None
_last_net_stat = None


def run_system_command(cmd_args, timeout=120, input_data=None):
    """
    Execute a system command safely.
    If the current process is not root, prepend 'sudo' if available.
    """
    if os.geteuid() != 0:
        if cmd_args[0] != 'sudo':
            cmd_args = ['sudo'] + cmd_args

    logger.info("Executing system command: %s", " ".join(cmd_args))
    try:
        process = subprocess.Popen(
            cmd_args,
            stdin=subprocess.PIPE if input_data is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        stdout, _ = process.communicate(input=input_data, timeout=timeout)
        return process.returncode, stdout
    except subprocess.TimeoutExpired:
        process.kill()
        return -1, "Command timed out after %s seconds." % timeout
    except Exception as e:
        logger.error("Command execution failed: %s", e)
        return -1, str(e)


def sync_system_password(username, new_password):
    """
    Sync password to Linux system user using chpasswd if the user exists.
    """
    try:
        # Check if user exists on linux system
        check_cmd = ['id', username]
        rc, _ = run_system_command(check_cmd)
        if rc == 0:
            cmd = ['chpasswd']
            if os.geteuid() != 0:
                cmd = ['sudo'] + cmd
            p = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = p.communicate(
                input=f"{username}:{new_password}\n", timeout=15)
            if p.returncode == 0:
                logger.info(
                    "Successfully updated system password for user: %s",
                    username)
                return True, "Password sistem Linux berhasil diperbarui."
            else:
                logger.warning(
                    "Failed to update system password for %s: %s", username,
                    stderr)
                return (
                    False, f"Gagal update password sistem: {stderr}")
        else:
            logger.warning("User %s not found on Linux system.", username)
            return (
                False,
                f"User '{username}' tidak ditemukan pada sistem Linux.")
    except Exception as e:
        logger.error("Error syncing system password: %s", e)
        return False, str(e)


def load_ipp_map(ipp_file='/var/log/openvpn/ipp.txt'):
    """
    Parse OpenVPN ifconfig-pool-persist file (ipp.txt).
    Returns a dict mapping username -> ip_address.
    """
    ipp_map = {}
    if not ipp_file:
        return ipp_map

    content = ""
    if os.path.exists(ipp_file):
        try:
            with open(ipp_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except PermissionError:
            rc, out = run_system_command(['cat', ipp_file])
            if rc == 0:
                content = out
            else:
                logger.warning(
                    "Failed to read ipp file %s via sudo: %s", ipp_file, out)
        except Exception as e:
            logger.warning("Failed to read ipp file %s: %s", ipp_file, e)
    else:
        # File might exist in directory restricted to root
        rc, out = run_system_command(['cat', ipp_file])
        if rc == 0:
            content = out

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';'):
            continue
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 2 and parts[0]:
            username = parts[0]
            ip = parts[1]
            if ip:
                ipp_map[username] = ip
                ipp_map[username.lower()] = ip

    return ipp_map


def is_proxy_file_exists(proxy_file='/var/log/openvpn/proxy.txt'):
    """
    Check if proxy_file exists on system.
    """
    if not proxy_file:
        return False
    if os.path.exists(proxy_file):
        return True
    rc, _ = run_system_command(['test', '-f', proxy_file])
    return rc == 0


def is_no_more_proxy(settings):
    """
    Check if openvpn.no_more_proxy is True (default True).
    """
    val = settings.get('openvpn.no_more_proxy', 'true')
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ('true', 'yes', '1', 't')


def get_proxy_info(proxy_file='/var/log/openvpn/proxy.txt'):
    """
    Read proxy-enabled user and optional ports from proxy_file.
    Format in proxy_file can be:
      - 'username'
      - 'username:port1,port2,...'
    Returns tuple: (username, ports) or (None, None).
    """
    if not proxy_file:
        return None, None

    content = ""
    if os.path.exists(proxy_file):
        try:
            with open(proxy_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except PermissionError:
            rc, out = run_system_command(['cat', proxy_file])
            if rc == 0:
                content = out
        except Exception as e:
            logger.warning("Failed to read proxy file %s: %s", proxy_file, e)
    else:
        rc, out = run_system_command(['cat', proxy_file])
        if rc == 0:
            content = out

    first_line = content.strip().splitlines()[0].strip() \
        if content.strip() else ""
    if not first_line:
        return None, None

    if ':' in first_line:
        parts = first_line.split(':', 1)
        user = parts[0].strip() or None
        ports = parts[1].strip() or None
        return user, ports
    else:
        return first_line.strip(), None


def get_proxy_user(proxy_file='/var/log/openvpn/proxy.txt'):
    """
    Read the single proxy-enabled username from proxy_file.
    Returns username string or None if not set or empty.
    """
    user, _ = get_proxy_info(proxy_file)
    return user


def get_proxy_ports(proxy_file='/var/log/openvpn/proxy.txt'):
    """
    Read the reverse proxy ports from proxy_file if format is 'username:ports'.
    Returns comma-separated ports string or None if not set.
    """
    _, ports = get_proxy_info(proxy_file)
    return ports


# Alias for backward compatibility if needed
get_reverse_proxy_ports = get_proxy_ports


def save_proxy_file(proxy_file, username, ports=None):
    """
    Save proxy user and optional ports to proxy_file.
    If ports is provided: '[username]:[ports]\n'
    Otherwise: '[username]\n'
    """
    if not username or not proxy_file:
        return False

    content = (f"{username.strip().lower()}:{ports.strip()}\n"
               if ports else f"{username.strip().lower()}\n")
    try:
        dir_name = os.path.dirname(proxy_file)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)
        with open(proxy_file, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except PermissionError:
        cmd = ['tee', proxy_file]
        rc, _ = run_system_command(cmd, input_data=content)
        return rc == 0
    except Exception as e:
        logger.error("Failed to write to proxy file %s: %s", proxy_file, e)
        return False


def set_proxy_user(username, ports=None,
                   proxy_file='/var/log/openvpn/proxy.txt',
                   firewall_cmd='/usr/local/bin/firewall',
                   **kwargs):
    """
    Set the proxy-enabled user by saving to proxy_file and executing
    firewall_cmd.
    Pilihan 1 (ports is None):
      Menyimpan [username] ke file proxy_file.
    Pilihan 2 (ports provided):
      Menyimpan [username]:[ports] ke file proxy_file.
    Setelah penyimpanan file, jalankan firewall_cmd tanpa argumen.
    """
    if not username:
        return False

    proxy_file = proxy_file or '/var/log/openvpn/proxy.txt'
    firewall_cmd = firewall_cmd or '/usr/local/bin/firewall'

    # 1. Simpan ke file proxy_file
    if not save_proxy_file(proxy_file, username, ports=ports):
        logger.error("Failed to save proxy user to %s", proxy_file)
        return False

    # 2. Jalankan firewall_cmd tanpa argumen
    rc, output = run_system_command([firewall_cmd])
    if rc != 0:
        logger.error(
            "Failed to execute %s: rc=%s, output=%s",
            firewall_cmd, rc, output
        )
        return False
    return True


def check_and_remove_proxy_user(
        username, proxy_file='/var/log/openvpn/proxy.txt'):
    """
    Check if proxy_file has username as the proxy user.
    If so, remove proxy_file.
    Returns True if proxy_file was removed, False otherwise.
    """
    if not username or not proxy_file:
        return False

    proxy_user = get_proxy_user(proxy_file)
    if proxy_user and proxy_user.strip().lower() == username.strip().lower():
        if os.path.exists(proxy_file):
            try:
                os.remove(proxy_file)
                logger.info(
                    "Proxy file %s berhasil dihapus untuk user %s",
                    proxy_file, username)
                return True
            except PermissionError:
                rc, _ = run_system_command(['rm', '-f', proxy_file])
                return rc == 0
            except Exception as e:
                logger.warning(
                    "Gagal menghapus file proxy %s: %s", proxy_file, e)
                return False
        else:
            rc, _ = run_system_command(['rm', '-f', proxy_file])
            return rc == 0
    return False


def revoke_user(username, revoke_cmd='/usr/local/bin/revoke-user',
                client_dir='/etc/openvpn/client',
                proxy_file=None):
    """
    Execute revoke_cmd (default: /usr/local/bin/revoke-user) [username]
    and remove [username].tgz from client_dir if revocation succeeds.
    Also remove proxy_file if the proxy user matches username.
    """
    if not username:
        return False, "Username tidak valid."

    cmd = [revoke_cmd, username.strip().lower()]
    rc, output = run_system_command(cmd)
    if rc != 0:
        logger.error(
            "Failed to execute %s %s: rc=%s, output=%s",
            revoke_cmd, username, rc, output
        )
        return False, output or f"Gagal mengeksekusi {revoke_cmd} (kode: {rc})"

    if client_dir:
        cert_path = os.path.join(client_dir, f"{username}.tgz")
        if os.path.exists(cert_path):
            try:
                os.remove(cert_path)
            except PermissionError:
                run_system_command(['rm', '-f', cert_path])
            except Exception as e:
                logger.warning(
                    "Gagal menghapus file cert %s: %s", cert_path, e)

    if proxy_file:
        check_and_remove_proxy_user(username, proxy_file=proxy_file)

    return True, output


def get_cert_details(client_dir, username, ipp_file='/var/log/openvpn/ipp.txt',
                     proxy_file='/var/log/openvpn/proxy.txt'):
    """
    Check if certificate archive exists and return details.
    """
    filepath = os.path.join(client_dir, f"{username}.tgz")
    ipp_map = load_ipp_map(ipp_file) if ipp_file else {}
    ip_addr = ipp_map.get(username, ipp_map.get(username.lower(), '-'))
    proxy_user = get_proxy_user(proxy_file) if proxy_file else None
    is_proxy = bool(proxy_user and username.lower() == proxy_user.lower())

    if os.path.exists(filepath):
        try:
            stat = os.stat(filepath)
            size_kb = round(stat.st_size / 1024, 2)
            mtime = datetime.fromtimestamp(
                stat.st_mtime).strftime('%d/%m/%Y %H:%M')
            return {
                'exists': True,
                'path': filepath,
                'filename': f"{username}.tgz",
                'size_kb': size_kb,
                'modified': mtime,
                'mtime_epoch': stat.st_mtime,
                'ip': ip_addr,
                'is_proxy': is_proxy,
            }
        except Exception as e:
            logger.error("Error reading cert file info: %s", e)
            return {
                'exists': True, 'path': filepath,
                'filename': f"{username}.tgz", 'size_kb': 0, 'modified': '-',
                'mtime_epoch': 0, 'ip': ip_addr, 'is_proxy': is_proxy}
    return {
        'exists': False, 'path': filepath, 'filename': f"{username}.tgz",
        'size_kb': 0, 'modified': '-', 'mtime_epoch': 0, 'ip': ip_addr,
        'is_proxy': is_proxy}


def list_client_certificates(client_dir, ipp_file='/var/log/openvpn/ipp.txt',
                             proxy_file='/var/log/openvpn/proxy.txt'):
    """
    Scan client_dir for *.tgz files and return a list of client info dicts.
    Each dict contains: username, filename, path, size_kb, modified,
    mtime_epoch, ip, is_proxy.
    """
    clients = []
    if not os.path.exists(client_dir) or not os.path.isdir(client_dir):
        logger.warning("Client directory does not exist: %s", client_dir)
        return clients

    ipp_map = load_ipp_map(ipp_file) if ipp_file else {}
    proxy_user = get_proxy_user(proxy_file) if proxy_file else None
    proxy_user_norm = proxy_user.strip().lower() if proxy_user else None

    try:
        filenames = os.listdir(client_dir)
    except Exception as e:
        logger.error("Failed to list client directory %s: %s", client_dir, e)
        return clients

    for fname in filenames:
        if fname.endswith('.tgz') and not fname.startswith('.'):
            username = fname[:-4]
            filepath = os.path.join(client_dir, fname)
            try:
                stat = os.stat(filepath)
                size_kb = round(stat.st_size / 1024, 2)
                mtime = datetime.fromtimestamp(
                    stat.st_mtime).strftime('%d/%m/%Y %H:%M')
                mtime_epoch = stat.st_mtime
            except Exception as e:
                logger.error("Error reading stat for %s: %s", filepath, e)
                size_kb = 0
                mtime = '-'
                mtime_epoch = 0

            ip_addr = ipp_map.get(username, ipp_map.get(username.lower(), '-'))
            is_proxy = bool(
                proxy_user_norm and username.lower() == proxy_user_norm)

            clients.append({
                'username': username,
                'filename': fname,
                'path': filepath,
                'size_kb': size_kb,
                'modified': mtime,
                'mtime_epoch': mtime_epoch,
                'ip': ip_addr,
                'ip_sumber': None,
                'is_proxy': is_proxy,
            })

    # Sort alphabetically by username
    clients.sort(key=lambda c: c['username'].lower())
    return clients


def is_linux_user_exists(username):
    """
    Check if a username is already registered in Linux (/etc/passwd).
    """
    if not username:
        return False
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        pass
    except Exception as e:
        logger.warning("pwd.getpwnam check error: %s", e)

    try:
        if os.path.exists('/etc/passwd'):
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if line.startswith(f"{username}:"):
                        return True
    except Exception as e:
        logger.warning("Error reading /etc/passwd: %s", e)

    return False


def get_system_stats():
    """
    Collect real-time CPU, RAM, Virtual RAM (swap), storage, and network TX/RX
    stats.
    Pure Python reading /proc and os.statvfs.
    """
    global _last_cpu_stat, _last_net_stat
    now = time.time()

    def _read_cpu_raw():
        try:
            with open('/proc/stat', 'r') as f:
                line = f.readline()
                if line.startswith('cpu '):
                    parts = [float(x) for x in line.split()[1:8]]
                    idle = parts[3] + parts[4]
                    total = sum(parts)
                    return idle, total
        except Exception as e:
            logger.error("Error reading /proc/stat: %s", e)
        return None, None

    # If first time, sample with small delay for initial CPU reading
    if _last_cpu_stat is None:
        i1, t1 = _read_cpu_raw()
        time.sleep(0.05)
        now = time.time()
        _last_cpu_stat = (i1, t1, now)

    idle_time, total_time = _read_cpu_raw()
    cpu_percent = 0.0
    if idle_time is not None and total_time is not None \
            and _last_cpu_stat[0] is not None:
        prev_idle, prev_total, _ = _last_cpu_stat
        diff_idle = idle_time - prev_idle
        diff_total = total_time - prev_total
        if diff_total > 0:
            cpu_percent = round(
                max(0.0, min(100.0, (1.0 - (diff_idle / diff_total)) * 100.0)),
                1)
        _last_cpu_stat = (idle_time, total_time, now)

    cpu_cores = os.cpu_count() or 1
    try:
        load_avg = [round(x, 2) for x in os.getloadavg()]
    except Exception:
        load_avg = [0.0, 0.0, 0.0]

    # RAM & Swap
    mem_info = {}
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split(':')
                if len(parts) == 2:
                    k = parts[0].strip()
                    v = parts[1].strip().split()[0]
                    if v.isdigit():
                        mem_info[k] = int(v)
    except Exception as e:
        logger.error("Error reading /proc/meminfo: %s", e)

    mem_total_kb = mem_info.get('MemTotal', 1)
    mem_avail_kb = mem_info.get('MemAvailable', mem_info.get('MemFree', 0))
    mem_used_kb = max(0, mem_total_kb - mem_avail_kb)
    ram_percent = round((
        mem_used_kb / mem_total_kb) * 100.0, 1) if mem_total_kb > 0 else 0.0
    ram_used_gb = round(mem_used_kb / (1024 * 1024), 2)
    ram_total_gb = round(mem_total_kb / (1024 * 1024), 2)

    swap_total_kb = mem_info.get('SwapTotal', 0)
    swap_free_kb = mem_info.get('SwapFree', 0)
    swap_used_kb = max(0, swap_total_kb - swap_free_kb)
    swap_percent = round((
        swap_used_kb / swap_total_kb) * 100.0, 1) if swap_total_kb > 0 else 0.0
    swap_used_gb = round(swap_used_kb / (1024 * 1024), 2)
    swap_total_gb = round(swap_total_kb / (1024 * 1024), 2)

    # Storage (root mount /)
    try:
        st = os.statvfs('/')
        disk_total_bytes = st.f_blocks * st.f_frsize
        disk_free_bytes = st.f_bavail * st.f_frsize
        disk_used_bytes = max(0, disk_total_bytes - disk_free_bytes)
        disk_percent = round((
            disk_used_bytes / disk_total_bytes) * 100.0, 1) \
            if disk_total_bytes > 0 else 0.0
        disk_used_gb = round(disk_used_bytes / (1024 ** 3), 2)
        disk_total_gb = round(disk_total_bytes / (1024 ** 3), 2)
    except Exception as e:
        logger.error("Error reading statvfs: %s", e)
        disk_percent = 0.0
        disk_used_gb = 0.0
        disk_total_gb = 0.0

    # Network RX / TX (Exclude loopback 'lo')
    curr_rx_bytes = 0
    curr_tx_bytes = 0
    try:
        with open('/proc/net/dev', 'r') as f:
            for line in f:
                if ':' in line:
                    iface, data = line.split(':', 1)
                    if iface.strip() != 'lo':
                        cols = data.split()
                        curr_rx_bytes += int(cols[0])
                        curr_tx_bytes += int(cols[8])
    except Exception as e:
        logger.error("Error reading net/dev: %s", e)

    rx_rate = 0.0
    tx_rate = 0.0
    if _last_net_stat is not None:
        prev_rx, prev_tx, prev_t = _last_net_stat
        dt = now - prev_t
        if dt > 0:
            rx_rate = max(0.0, (curr_rx_bytes - prev_rx) / dt)
            tx_rate = max(0.0, (curr_tx_bytes - prev_tx) / dt)
    _last_net_stat = (curr_rx_bytes, curr_tx_bytes, now)

    def _fmt_speed(bps):
        if bps >= 1024 * 1024:
            return f"{bps / (1024 * 1024):.2f} MB/s"
        elif bps >= 1024:
            return f"{bps / 1024:.1f} KB/s"
        else:
            return f"{int(bps)} B/s"

    # Percentage for network: relative to 100 Mbps (12.5 MB/s) baseline, capped
    # at 100%
    net_capacity_bps = 12.5 * 1024 * 1024
    rx_percent = min(100.0, round((rx_rate / net_capacity_bps) * 100.0, 1))
    tx_percent = min(100.0, round((tx_rate / net_capacity_bps) * 100.0, 1))

    return {
        'cpu': {
            'percent': cpu_percent,
            'cores': cpu_cores,
            'load_avg': load_avg,
        },
        'ram': {
            'percent': ram_percent,
            'used_gb': ram_used_gb,
            'total_gb': ram_total_gb,
        },
        'swap': {
            'percent': swap_percent,
            'used_gb': swap_used_gb,
            'total_gb': swap_total_gb,
        },
        'disk': {
            'percent': disk_percent,
            'used_gb': disk_used_gb,
            'total_gb': disk_total_gb,
        },
        'network': {
            'rx_rate': rx_rate,
            'tx_rate': tx_rate,
            'rx_speed_str': _fmt_speed(rx_rate),
            'tx_speed_str': _fmt_speed(tx_rate),
            'rx_percent': rx_percent,
            'tx_percent': tx_percent,
            'rx_total_mb': round(curr_rx_bytes / (1024 * 1024), 1),
            'tx_total_mb': round(curr_tx_bytes / (1024 * 1024), 1),
        },
        'timestamp': now,
    }


def generate_totp_secret():
    """Generate a random Base32 TOTP secret string."""
    import pyotp
    return pyotp.random_base32()


def generate_totp_uri(secret, username, issuer='WebminOpenVPN'):
    """Generate otpauth:// URI for Google Authenticator."""
    import pyotp
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name=issuer)


def generate_totp_qr_svg_base64(secret, username, issuer='WebminOpenVPN'):
    """Generate Base64-encoded SVG data URI of the QR code."""
    import qrcode
    import qrcode.image.svg
    import io
    import base64

    uri = generate_totp_uri(secret, username, issuer=issuer)
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    return f"data:image/svg+xml;base64,{b64}"


def format_totp_secret(secret):
    """Format Base32 secret into 4-character chunks for manual entry."""
    if not secret:
        return ""
    clean = secret.replace(" ", "").upper()
    return " ".join(clean[i:i + 4] for i in range(0, len(clean), 4))


def validate_ip_list(text):
    """
    Validates that each line in text is either an IPv4 address or
    empty/whitespace.
    Returns:
        tuple (is_valid: bool, ips: list[str], error_message: str or None)
    """
    if not text:
        return True, [], None

    ips = []
    lines = text.splitlines()
    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            ip_obj = ipaddress.IPv4Address(line)
            ips.append(str(ip_obj))
        except ValueError:
            return (
                False,
                [],
                f'Baris {idx} ("{line}") bukan alamat IPv4 yang valid.',
            )

    seen = set()
    unique_ips = [ip for ip in ips if not (ip in seen or seen.add(ip))]
    return True, unique_ips, None


def read_ip_list_file(filepath):
    """
    Read IP list file if exists, return string.
    If file doesn't exist, return empty string.
    """
    if not filepath:
        return ""
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except PermissionError:
            rc, out = run_system_command(['cat', filepath])
            if rc == 0:
                return out
            return ""
        except Exception as e:
            logger.warning("Failed to read %s: %s", filepath, e)
            return ""
    else:
        rc, out = run_system_command(['cat', filepath])
        if rc == 0:
            return out
        return ""


def save_ip_list_file(filepath, ips):
    """
    If ips is non-empty list of IP strings, write to filepath (one per line).
    If ips is empty, remove filepath if it exists.
    """
    if not filepath:
        return False

    if ips:
        content = "\n".join(ips) + "\n"
        dirname = os.path.dirname(filepath)
        if dirname and not os.path.exists(dirname):
            try:
                os.makedirs(dirname, exist_ok=True)
            except PermissionError:
                run_system_command(['mkdir', '-p', dirname])

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except PermissionError:
            cmd = ['tee', filepath]
            if os.geteuid() != 0:
                cmd = ['sudo'] + cmd
            p = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            _, err = p.communicate(input=content, timeout=15)
            if p.returncode != 0:
                logger.error(
                    "Failed to write %s via sudo tee: %s", filepath, err)
                return False
            return True
        except Exception as e:
            logger.error("Failed to write %s: %s", filepath, e)
            return False
    else:
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                return True
            except PermissionError:
                rc, _ = run_system_command(['rm', '-f', filepath])
                return rc == 0
            except Exception as e:
                logger.error("Failed to remove %s: %s", filepath, e)
                return False
        else:
            rc, _ = run_system_command(['rm', '-f', filepath])
            return True
