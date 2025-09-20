import logging
from datetime import datetime

# Logging setup
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def log_info(message: str):
    logging.info(message)

def log_error(message: str):
    logging.error(message)

def format_timestamp(ts: float) -> str:
    """Convert UNIX timestamp to readable string."""
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
