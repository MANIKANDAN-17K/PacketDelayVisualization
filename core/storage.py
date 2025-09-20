import sqlite3
from datetime import datetime

class Storage:
    def __init__(self, db_path='database/history.db'):
        self.conn = sqlite3.connect(db_path)
        self.create_table()

    def create_table(self):
        query = """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            timestamp TEXT,
            app_name TEXT,
            delay REAL,
            jitter REAL
        )
        """
        self.conn.execute(query)
        self.conn.commit()

    def save_session(self, name, app_name, delay, jitter):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        query = "INSERT INTO sessions (name, timestamp, app_name, delay, jitter) VALUES (?, ?, ?, ?, ?)"
        self.conn.execute(query, (name, ts, app_name, delay, jitter))
        self.conn.commit()

    def get_recent_sessions(self, limit=5):
        query = "SELECT * FROM sessions ORDER BY timestamp DESC LIMIT ?"
        cursor = self.conn.execute(query, (limit,))
        sessions = []
        for row in cursor.fetchall():
            sessions.append({
                "id": row[0],
                "name": row[1],
                "timestamp": row[2],
                "app_name": row[3],
                "delay": row[4],
                "jitter": row[5]
            })
        return sessions
