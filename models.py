import sqlite3
from datetime import datetime
import uuid
import csv


# inisialisasi database
def init_db():
    with sqlite3.connect("users.db") as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE,
                            password TEXT,
                            token TEXT,
                            role TEXT
                        )''')

# Logging ke CSV untuk admin
def custom_log(key, txt, session_user, ip, app_name='WEBAPP'):
    uuid_str = str(uuid.uuid4())
    waktu = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = [uuid_str, key, txt, session_user, ip, app_name, waktu]
    with open('logs/activity.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(log_entry)