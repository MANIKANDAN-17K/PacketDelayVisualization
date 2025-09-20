from PyQt5.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout
from PyQt5.QtCore import QTimer

from ui.app_list_panel import AppListPanel
from ui.graphs_panel import GraphsPanel
from ui.history_panel import HistoryPanel

from core.packet_processor import PacketProcessor
from core.storage import Storage

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Delay Visualizer")
        self.resize(1400, 800)

        # Core modules
        self.packet_processor = PacketProcessor()  # live capture & Wireshark parsing
        self.storage = Storage()                  # SQLite history

        main_layout = QHBoxLayout()
        left_layout = QVBoxLayout()
        right_layout = QVBoxLayout()

        # Left: Apps + History
        self.app_list = AppListPanel()
        self.history_panel = HistoryPanel(storage=self.storage)
        left_layout.addWidget(self.app_list)
        left_layout.addWidget(self.history_panel)

        # Right: Graphs
        self.graphs_panel = GraphsPanel()
        right_layout.addWidget(self.graphs_panel)

        main_layout.addLayout(left_layout, 2)
        main_layout.addLayout(right_layout, 5)
        self.setLayout(main_layout)

        # Timer for live updates
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_live_data)
        self.timer.start(1000)  # update every 1 second

    def update_live_data(self):
        # Get newly captured packets
        packets = self.packet_processor.get_new_packets()

        # Update active apps list
        active_apps = self.packet_processor.get_active_apps()
        self.app_list.update_apps(active_apps)

        # Update selected app charts
        selected_app = self.app_list.get_selected_app()
        if selected_app:
            data = self.packet_processor.get_app_data(selected_app)
            self.graphs_panel.delay_data = data['delay']
            self.graphs_panel.jitter_data = data['jitter']
            self.graphs_panel.plot_charts()

        # Update history panel if needed
        self.history_panel.refresh()