import sqlite3
import streamlit as st
import datetime
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
    conn.commit()
    conn.close()

@st.cache_resource
def get_db_connection():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def save_attack_to_db(alert):
    conn = get_db_connection()
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
    conn.commit()
    # Update dictionary id to match database
    alert['id'] = alert_id
    alert['city'] = city
    alert['country'] = country
    alert['latitude'] = lat
    alert['longitude'] = lon
    return alert_id

def get_all_logs(limit=100):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM attack_logs ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

def get_active_logs_count():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE status='ACTIVE'")
    return cursor.fetchone()[0]

def get_total_malicious_count():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM attack_logs")
    return cursor.fetchone()[0]

def block_ip_db(ip):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR IGNORE INTO blocked_ips (ip, date_added)
        VALUES (?, ?)
    ''', (ip, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()

def unblock_ip_db(ip):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
    conn.commit()

def get_blocked_ips_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT ip FROM blocked_ips')
    rows = cursor.fetchall()
    return set(row[0] for row in rows)

def clear_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM attack_logs')
    cursor.execute('DELETE FROM blocked_ips')
    conn.commit()
