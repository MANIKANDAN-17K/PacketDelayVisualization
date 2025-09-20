import psutil

class AppClassifier:
    def __init__(self):
        self.port_to_app = self.build_port_map()

    def build_port_map(self):
        """
        Map active ports → process names.
        """
        port_map = {}
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                for conn in proc.connections(kind='inet'):
                    if conn.status == 'ESTABLISHED':
                        port_map[conn.laddr.port] = proc.info['name']
            except Exception:
                continue
        return port_map

    def classify_packet(self, src_port, dst_port):
        """
        Map packet ports to an app name.
        """
        return self.port_to_app.get(src_port) or self.port_to_app.get(dst_port)


# Optional helper function
def get_active_apps():
    active_apps = set()
    for proc in psutil.process_iter(['name']):
        try:
            for conn in proc.connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    active_apps.add(proc.info['name'])
        except Exception:
            continue
    return list(active_apps)
