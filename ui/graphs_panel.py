from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QComboBox
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt
from PyQt5.QtCore import QTimer

from core.network_metrics import NetworkMetrics
from core.packet_processor import PacketProcessor

class GraphsPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Chart type selector
        self.chart_type = QComboBox()
        self.chart_type.addItems(["Line", "Bar", "Histogram"])
        layout.addWidget(QLabel("Select Chart Type"))
        layout.addWidget(self.chart_type)

        # Network strength
        self.network_label = QLabel("Network Strength: Good")
        layout.addWidget(self.network_label)

        # Delay chart
        self.figure, self.ax = plt.subplots()
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        # Jitter chart
        self.figure_jitter, self.ax_jitter = plt.subplots()
        self.canvas_jitter = FigureCanvas(self.figure_jitter)
        layout.addWidget(self.canvas_jitter)

        # Live button
        self.live_button = QPushButton("Start Live")
        self.live_button.setCheckable(True)
        self.live_button.clicked.connect(self.toggle_live)
        layout.addWidget(self.live_button)

        # Packet processor
        self.packet_processor = PacketProcessor()
        self.delay_data = []
        self.jitter_data = []
        self.selected_app = None

        # Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_live_data)

    def set_selected_app(self, app_name: str):
        """
        Set the currently selected app to display its delay/jitter.
        """
        self.selected_app = app_name
        self.refresh_graphs()

    def update_live_data(self):
        """
        Called every second if live mode is active.
        """
        if self.selected_app:
            app_data = self.packet_processor.get_app_data(self.selected_app)
            if app_data:
                self.delay_data = app_data['delay']
                self.jitter_data = app_data['jitter']
                self.refresh_graphs()

    def refresh_graphs(self):
        """
        Plot the charts based on current data and selected chart type.
        """
        # Delay chart
        self.ax.clear()
        if self.chart_type.currentText() == "Line":
            self.ax.plot(self.delay_data, label="Delay (ms)")
        elif self.chart_type.currentText() == "Bar":
            self.ax.bar(range(len(self.delay_data)), self.delay_data, label="Delay (ms)")
        elif self.chart_type.currentText() == "Histogram":
            self.ax.hist(self.delay_data, bins=20, label="Delay (ms)")
        self.ax.legend()
        self.canvas.draw()

        # Jitter chart
        self.ax_jitter.clear()
        if self.chart_type.currentText() == "Line":
            self.ax_jitter.plot(self.jitter_data, label="Jitter (ms)")
        elif self.chart_type.currentText() == "Bar":
            self.ax_jitter.bar(range(len(self.jitter_data)), self.jitter_data, label="Jitter (ms)")
        elif self.chart_type.currentText() == "Histogram":
            self.ax_jitter.hist(self.jitter_data, bins=20, label="Jitter (ms)")
        self.ax_jitter.legend()
        self.canvas_jitter.draw()

        # Update network strength
        self.network_label.setText(f"Network Strength: {NetworkMetrics.get_network_strength()}")

    def toggle_live(self):
        """
        Start or stop live update.
        """
        if self.live_button.isChecked():
            self.live_button.setText("Stop Live")
            self.timer.start(1000)
        else:
            self.live_button.setText("Start Live")
            self.timer.stop()
