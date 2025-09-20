from collections import deque

class PacketProcessor:
    def __init__(self, max_samples=50):
        self.max_samples = max_samples
        self.data = {}  # {app_name: {'delay': deque, 'jitter': deque}}
        self.last_timestamp = {}  # {app_name: last_packet_time}

    def process_packet(self, app_name, packet_time):
        """
        app_name: string
        packet_time: float (timestamp from packet)
        """
        if app_name not in self.data:
            self.data[app_name] = {
                'delay': deque(maxlen=self.max_samples),
                'jitter': deque(maxlen=self.max_samples)
            }
            self.last_timestamp[app_name] = None

        last_time = self.last_timestamp[app_name]
        if last_time is not None:
            delay = packet_time - last_time
            self.data[app_name]['delay'].append(delay)

            # Calculate jitter as difference between last two delays if possible
            delays = self.data[app_name]['delay']
            if len(delays) > 1:
                jitter = abs(delays[-1] - delays[-2])
                self.data[app_name]['jitter'].append(jitter)
            else:
                self.data[app_name]['jitter'].append(0)
        else:
            # For the first packet, no delay, no jitter
            self.data[app_name]['delay'].append(0)
            self.data[app_name]['jitter'].append(0)

        self.last_timestamp[app_name] = packet_time
