import psutil

class NetworkMetrics:
    @staticmethod
    def get_network_strength():
        """
        Returns a string indicating network strength based on speed.
        """
        try:
            stats = psutil.net_io_counters()
            speed = stats.bytes_sent + stats.bytes_recv
            if speed < 1e5:
                return "Poor"
            elif speed < 5e5:
                return "Average"
            return "Good"
        except Exception:
            return "Unknown"
