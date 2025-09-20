import psutil
import socket

def get_active_apps():
    """Return list of running apps with network connections (ignore system)."""
    apps = []
    for proc in psutil.process_iter(['name', 'pid']):
        try:
            if proc.connections(kind='inet'):
                apps.append(proc.info['name'])
        except Exception:
            continue
    return list(set(apps))

def get_device_ip():
    """Return the main IP of the device."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't have to connect, just for local IP
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_network_interfaces():
    """Return list of active network interfaces."""
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == 'AF_INET':
                interfaces.append(iface)
    return interfaces
