from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget, QListWidgetItem
from core.classifier import get_active_apps  # assume this returns a list

class AppListPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Active Network Apps"))

        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        self.setLayout(layout)

        # Active apps list
        self.active_apps = []

        # Signal selected app
        self.list_widget.currentItemChanged.connect(self.on_app_selected)

    def update_apps(self, apps):
        """
        Update the list widget with currently active apps.
        apps: list of app names
        """
        self.list_widget.clear()
        self.active_apps = apps
        for app_name in apps:
            item = QListWidgetItem(app_name)
            self.list_widget.addItem(item)

    def get_selected_app(self) -> str:
        """
        Returns the currently selected app name
        """
        item = self.list_widget.currentItem()
        if item:
            return item.text()
        return None

    def on_app_selected(self, current, previous):
        """
        Slot triggered when user selects an app
        """
        # You can emit a signal here if you want graphs_panel to update
        pass
