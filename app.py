from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3
import uuid
import os
from datetime import timedelta, datetime
import logging
from itsdangerous import URLSafeSerializer
import csv
from io import StringIO

# Init app
app = Flask(__name__)
app.secret_key = 'your-secret-key'
app.permanent_session_lifetime = timedelta(minutes=30)

# Token serializer
s = URLSafeSerializer(app.secret_key)

# Logging
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(filename='logs/activity.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Inisialisasi database
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

# Home
@app.route('/')
def index():
    if 'user' in session:
        token = s.dumps(session['user'])
        return redirect(url_for('secure_profile', token=token))
    return redirect(url_for('login'))

# Register
@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        token = s.dumps(username)  # ✅ Gunakan serializer token
        role = 'user'
        try:
            with sqlite3.connect("users.db") as conn:
                conn.execute("INSERT INTO users (username, password, token, role) VALUES (?, ?, ?, ?)",
                             (username, password, token, role))
                logging.info(f"REGISTER: {username}")
                flash("Register berhasil. Silakan login.", "success")
        except sqlite3.IntegrityError:
            flash("Username sudah digunakan.", "danger")
            logging.warning(f"REGISTER FAIL: {username} already exists")
        return redirect(url_for('login'))
    return render_template("register.html")

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect("users.db") as conn:
            cursor = conn.execute("SELECT * FROM users WHERE username=? AND password=?",
                                  (username, password))
            user = cursor.fetchone()
            if user:
                session.permanent = True
                session['user'] = username
                session['role'] = user[4]
                token = s.dumps(username)
                logging.info(f"LOGIN SUCCESS: {username}")
                custom_log("LOGIN", "/login", username, request.remote_addr)
                return redirect(url_for('secure_profile', token=token))
            else:
                flash("Username/password salah.", "danger")
                custom_log("INTRUDER", "/login", "GUEST", request.remote_addr)
                logging.warning(f"LOGIN FAIL: {username}")
    return render_template("login.html")

# Dashboard user/admin
@app.route('/profilesecure/<token>')
def secure_profile(token):
    try:
        username = s.loads(token)
        if 'user' in session and session['user'] == username:
            if session.get('role') == 'admin':
                return redirect(url_for('view_logs'))
            else:
                custom_log("Access", "/profilesecure", username, request.remote_addr)
                return render_template("dashboard.html", username=username)
        else:
            return "Unauthorized", 403
    except Exception as e:
        logging.error(f"INVALID TOKEN: {e}")
        return "Invalid token", 400

# Admin melihat log
@app.route('/admin/logs', methods=['GET'])
def view_logs():
    if 'user' in session and session.get('role') == 'admin':
        logs = []
        tanggal_filter = request.args.get('tanggal')

        try:
            with open('logs/activity.csv', 'r') as f:
                reader = csv.reader(f)
                for idx, row in enumerate(reader, start=1):
                    if not tanggal_filter or tanggal_filter in row[-1]:
                        logs.append([idx] + row)
        except FileNotFoundError:
            logs = []

        return render_template("admin_dashboard.html", username=session['user'], logs=logs, tanggal_filter=tanggal_filter)
    else:
        return "Unauthorized", 403

# Download CSV log
@app.route('/admin/download-logs')
def download_logs():
    if 'user' in session and session.get('role') == 'admin':
        try:
            with open('logs/activity.csv', 'r') as f:
                csv_content = f.read()
            return send_file(
                StringIO(csv_content),
                mimetype='text/csv',
                as_attachment=True,
                download_name='activity_logs.csv'
            )
        except FileNotFoundError:
            return "No log file found", 404
    return "Unauthorized", 403

# Logout
@app.route('/logout')
def logout():
    user = session.pop('user', None)
    logging.info(f"LOGOUT: {user}")
    flash("Kamu telah logout.", "info")
    return redirect(url_for('login'))

# Jalankan aplikasi
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
