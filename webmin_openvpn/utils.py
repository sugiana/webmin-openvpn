import os
import time
import pwd
import subprocess
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# State tracking for CPU and Network delta rate calculations
_last_cpu_stat = None
_last_net_stat = None


def run_system_command(cmd_args, timeout=120):
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
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        stdout, _ = process.communicate(timeout=timeout)
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


def get_cert_details(client_dir, username):
    """
    Check if certificate archive exists and return details.
    """
    filepath = os.path.join(client_dir, f"{username}.tgz")
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
            }
        except Exception as e:
            logger.error("Error reading cert file info: %s", e)
            return {
                'exists': True, 'path': filepath,
                'filename': f"{username}.tgz", 'size_kb': 0, 'modified': '-',
                'mtime_epoch': 0}
    return {
        'exists': False, 'path': filepath, 'filename': f"{username}.tgz",
        'size_kb': 0, 'modified': '-', 'mtime_epoch': 0}


def list_client_certificates(client_dir):
    """
    Scan client_dir for *.tgz files and return a list of client info dicts.
    Each dict contains: username, filename, path, size_kb, modified,
    mtime_epoch.
    """
    clients = []
    if not os.path.exists(client_dir) or not os.path.isdir(client_dir):
        logger.warning("Client directory does not exist: %s", client_dir)
        return clients

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

            clients.append({
                'username': username,
                'filename': fname,
                'path': filepath,
                'size_kb': size_kb,
                'modified': mtime,
                'mtime_epoch': mtime_epoch,
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
