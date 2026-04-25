import sqlite3
import streamlit as st
import datetime
import hashlib
from pathlib import Path
from geo_utils import get_ip_geolocation

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "iids_logs.db"

def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    
    # Migrating tables (Drop if outdated)
    try:
        cursor.execute("SELECT alert_sent FROM attack_logs LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("DROP TABLE IF EXISTS attack_logs")
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            attack_type TEXT,
            severity TEXT,
            anomaly_score REAL,
            malicious_probability REAL,
            details TEXT,
            status TEXT,
            shap_explanation TEXT,
            city TEXT,
            country TEXT,
            latitude REAL,
            longitude REAL,
            alert_sent INTEGER DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            date_added TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT,
            email TEXT UNIQUE,
            company_name TEXT,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    """Create a fresh SQLite connection for each call (thread-safe)."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def save_attack_to_db(alert):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        ts = alert.get('timestamp', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        src_ip = alert.get('src_ip', '')
        
        city, country, lat, lon = get_ip_geolocation(src_ip)
        
        # Testing Fallback (CRITICAL): Double check nulls before insert
        if lat is None or lon is None or lat == 0 or lon == 0:
            from geo_utils import _get_mock_location
            city, country, lat, lon = _get_mock_location()
        
        cursor.execute('''
            INSERT INTO attack_logs (timestamp, src_ip, dst_ip, attack_type, severity, anomaly_score, malicious_probability, details, status, shap_explanation, city, country, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ts,
            src_ip,
            alert.get('dst_ip', ''),
            alert.get('attack_type', 'Unknown'),
            alert.get('severity', 'NORMAL'),
            float(alert.get('anomaly_score', 0.0)),
            float(alert.get('malicious_probability', 0.0)),
            alert.get('details', ''),
            alert.get('status', 'ACTIVE'),
            alert.get('shap_explanation', ''),
            city,
            country,
            lat,
            lon
        ))
        alert_id = cursor.lastrowid
        # Update dictionary id to match database
        alert['id'] = alert_id
        alert['city'] = city
        alert['country'] = country
        alert['latitude'] = lat
        alert['longitude'] = lon
        return alert_id
    finally:
        conn.close()

def get_all_logs(limit=100):
    conn = get_db_connection()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM attack_logs ORDER BY id DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_active_logs_count():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE status='ACTIVE'")
        return cursor.fetchone()[0]
    finally:
        conn.close()

def get_total_malicious_count():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM attack_logs")
        return cursor.fetchone()[0]
    finally:
        conn.close()

def block_ip_db(ip):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO blocked_ips (ip, date_added)
            VALUES (?, ?)
        ''', (ip, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    finally:
        conn.close()

def unblock_ip_db(ip):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
    finally:
        conn.close()

def get_blocked_ips_db():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT ip FROM blocked_ips')
        rows = cursor.fetchall()
        return set(row[0] for row in rows)
    finally:
        conn.close()

def clear_db():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM attack_logs')
        cursor.execute('DELETE FROM blocked_ips')
    finally:
        conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(full_name, email, company_name, password):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (full_name, email, company_name, password)
            VALUES (?, ?, ?, ?)
        ''', (full_name, email, company_name, hash_password(password)))
        return True, "Registration successful."
    except sqlite3.IntegrityError:
        return False, "Email already exists. Please login."
    except Exception as e:
        return False, f"Error: {str(e)}"
    finally:
        conn.close()

def authenticate_user(email, password):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT full_name, company_name FROM users WHERE email = ? AND password = ?', 
                       (email, hash_password(password)))
        user = cursor.fetchone()
        if user:
            return True, {"full_name": user[0], "company_name": user[1]}
        return False, None
    finally:
        conn.close()

