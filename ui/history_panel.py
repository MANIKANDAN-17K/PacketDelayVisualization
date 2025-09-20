from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QListWidget, QListWidgetItem
from core.storage import Storage

class HistoryPanel(QWidget):
    def __init__(self, storage: Storage):
        super().__init__()
        self.storage = storage

        self.layout = QVBoxLayout()
        self.layout.addWidget(QLabel("Analysis History"))

        self.session_list = QListWidget()
        self.layout.addWidget(self.session_list)

        self.view_all_button = QPushButton("View All Sessions")
        self.view_all_button.clicked.connect(self.view_all_sessions)
        self.layout.addWidget(self.view_all_button)

        self.setLayout(self.layout)

        # Load initial sessions
        self.refresh()

    def refresh(self):
        """
        Refresh the list of history sessions.
        """
        self.session_list.clear()
        sessions = self.storage.get_recent_sessions(limit=5)
        for session in sessions:
            item = QListWidgetItem(f"{session['name']} - {session['timestamp']}")
            self.session_list.addItem(item)

    def view_all_sessions(self):
        """
        Placeholder: open a detailed history window.
        """
        # For now, just refresh list (can be expanded)
        self.refresh()
