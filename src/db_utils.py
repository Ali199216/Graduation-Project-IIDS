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
    
    # Migrate analysis_sessions: add attack_distribution column if missing
    try:
        cursor.execute("SELECT attack_distribution FROM analysis_sessions LIMIT 1")
    except sqlite3.OperationalError:
        try:
            cursor.execute("ALTER TABLE analysis_sessions ADD COLUMN attack_distribution TEXT DEFAULT ''")
        except:
            pass
    
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
            alert_sent INTEGER DEFAULT 0,
            alert_sent INTEGER DEFAULT 0
        )
    ''')
    try:
        cursor.execute("SELECT attack_type FROM blocked_ips LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("DROP TABLE IF EXISTS blocked_ips")
        
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            attack_type TEXT,
            date_added TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT,
            email TEXT UNIQUE,
            company_name TEXT,
            password TEXT,
            profile_pic TEXT
        )
    ''')
    # Migrate users: add profile_pic column if missing
    try:
        cursor.execute("SELECT profile_pic FROM users LIMIT 1")
    except sqlite3.OperationalError:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN profile_pic TEXT")
        except:
            pass
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_sessions (
            session_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            filename TEXT,
            timestamp TEXT,
            total_flows INTEGER,
            total_threats INTEGER,
            total_blocked INTEGER,
            map_data_json TEXT,
            attack_distribution TEXT,
            report_path TEXT
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

def block_ip_db(ip, attack_type="Manual Block"):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO blocked_ips (ip, attack_type, date_added)
            VALUES (?, ?, ?)
        ''', (ip, attack_type, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
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

def get_blocked_ips_detailed():
    """Get blocked IPs with their block timestamp, attack type, coordinates, and anomaly metrics."""
    conn = get_db_connection()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT b.ip, b.date_added,
                   COALESCE(a.attack_type, 'Manual Block') AS attack_type,
                   COALESCE(a.severity, 'N/A') AS severity,
                   COALESCE(a.latitude, 0) AS latitude,
                   COALESCE(a.longitude, 0) AS longitude,
                   COALESCE(a.city, 'Unknown') AS city,
                   COALESCE(a.country, 'Unknown') AS country,
                   COALESCE(a.anomaly_score, 0.0) AS anomaly_score,
                   COALESCE(a.malicious_probability, 0.0) AS malicious_probability,
                   COALESCE(s.total_hits, 1) AS total_hits
            FROM blocked_ips b
            LEFT JOIN (
                SELECT src_ip, attack_type, severity, latitude, longitude, city, country,
                       anomaly_score, malicious_probability,
                       ROW_NUMBER() OVER (PARTITION BY src_ip ORDER BY id DESC) AS rn
                FROM attack_logs
            ) a ON b.ip = a.src_ip AND a.rn = 1
            LEFT JOIN (
                SELECT src_ip, COUNT(*) AS total_hits
                FROM attack_logs
                GROUP BY src_ip
            ) s ON b.ip = s.src_ip
            ORDER BY b.date_added DESC
        ''')
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_normal_vs_attack_baseline(ip):
    """Build a Normal vs Attack comparison for a blocked IP.
    
    Returns dict with normal baselines (from overall benign averages) 
    vs the actual attack metrics that triggered the block.
    """
    conn = get_db_connection()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get the attack metrics for this IP (most recent attack)
        cursor.execute('''
            SELECT anomaly_score, malicious_probability, attack_type, severity
            FROM attack_logs WHERE src_ip = ? ORDER BY id DESC LIMIT 1
        ''', (ip,))
        attack_row = cursor.fetchone()
        
        if not attack_row:
            return None
        
        attack_data = dict(attack_row)
        
        # Get average metrics across ALL attacks from this IP
        cursor.execute('''
            SELECT AVG(anomaly_score) as avg_anomaly,
                   MAX(malicious_probability) as max_prob,
                   COUNT(*) as hit_count
            FROM attack_logs WHERE src_ip = ?
        ''', (ip,))
        agg_row = cursor.fetchone()
        agg = dict(agg_row) if agg_row else {}
        
        # Normal baselines (representative of benign traffic)
        # These are typical values for clean traffic
        normal_baselines = {
            'anomaly_score': 0.02,
            'malicious_probability': 0.05,
            'threat_level': 'NONE',
            'status': 'BENIGN',
        }
        
        # Attack observed values
        attack_observed = {
            'anomaly_score': round(attack_data.get('anomaly_score', 0), 4),
            'malicious_probability': round(attack_data.get('malicious_probability', 0), 4),
            'threat_level': attack_data.get('severity', 'N/A'),
            'attack_type': attack_data.get('attack_type', 'Unknown'),
            'avg_anomaly': round(agg.get('avg_anomaly', 0) or 0, 4),
            'max_probability': round(agg.get('max_prob', 0) or 0, 4),
            'total_detections': agg.get('hit_count', 0),
        }
        
        return {
            'normal': normal_baselines,
            'attack': attack_observed,
        }
    finally:
        conn.close()


def get_attacker_profile(ip):
    """Build a full attacker dossier for a given IP address."""
    conn = get_db_connection()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        # Get all attacks from this IP
        cursor.execute('''
            SELECT attack_type, severity, timestamp, dst_ip, anomaly_score, city, country
            FROM attack_logs WHERE src_ip = ? ORDER BY id DESC
        ''', (ip,))
        rows = [dict(r) for r in cursor.fetchall()]
        
        if not rows:
            return None
        
        attack_types = list(set(r['attack_type'] for r in rows if r.get('attack_type')))
        total_hits = len(rows)
        severities = [r['severity'] for r in rows if r.get('severity')]
        countries = list(set(r['country'] for r in rows if r.get('country')))
        cities = list(set(r['city'] for r in rows if r.get('city')))
        
        # Risk level
        if total_hits >= 10 or 'CRITICAL' in severities:
            risk = 'HIGH'
        elif total_hits >= 4 or 'HIGH' in severities:
            risk = 'MEDIUM'
        else:
            risk = 'LOW'
        
        # Behavioral tags
        tags = []
        if total_hits >= 8: tags.append('Persistent Scanner')
        if any(t in attack_types for t in ['DoS']): tags.append('High-Volume Flooder')
        if any(t in attack_types for t in ['Reconnaissance']): tags.append('Network Prober')
        if any(t in attack_types for t in ['Backdoor']): tags.append('Covert Access Agent')
        if any(t in attack_types for t in ['Exploits']): tags.append('Vulnerability Exploiter')
        if any(t in attack_types for t in ['Shellcode']): tags.append('Code Injector')
        if any(t in attack_types for t in ['Worms']): tags.append('Self-Propagator')
        if any(t in attack_types for t in ['Fuzzers']): tags.append('Input Fuzzer')
        if len(attack_types) >= 3: tags.append('Multi-Vector Attacker')
        if not tags: tags.append('Unclassified Threat')
        
        return {
            'ip': ip,
            'total_hits': total_hits,
            'risk': risk,
            'tags': tags,
            'attack_types': attack_types,
            'countries': countries,
            'cities': cities,
            'first_seen': rows[-1].get('timestamp', 'N/A'),
            'last_seen': rows[0].get('timestamp', 'N/A'),
            'recent_attacks': rows[:5],
        }
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

def clear_blocklist_db():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
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

def update_user_profile_pic(email, base64_img):
    """Save the profile picture Base64 string to the database."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET profile_pic = ? WHERE email = ?", (base64_img, email))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating profile pic: {e}")
        return False
    finally:
        conn.close()

def authenticate_user(email, password):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT full_name, company_name, profile_pic FROM users WHERE email = ? AND password = ?', 
                       (email, hash_password(password)))
        user = cursor.fetchone()
        if user:
            return True, {"full_name": user[0], "company_name": user[1], "profile_pic": user[2]}
        return False, None
    finally:
        conn.close()


# ---- Session History Functions ----

def save_session(user_email, filename, total_flows, total_threats, total_blocked, map_data_json, attack_distribution="", report_path=""):
    """Save a completed analysis session to the archive."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO analysis_sessions (user_email, filename, timestamp, total_flows, total_threats, total_blocked, map_data_json, attack_distribution, report_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_email,
            filename,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_flows,
            total_threats,
            total_blocked,
            map_data_json,
            attack_distribution,
            report_path
        ))
        return cursor.lastrowid
    finally:
        conn.close()

def get_sessions(user_email=""):
    """Get all analysis sessions, optionally filtered by user. Newest first."""
    conn = get_db_connection()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if user_email:
            cursor.execute('SELECT * FROM analysis_sessions WHERE user_email = ? ORDER BY session_id DESC', (user_email,))
        else:
            cursor.execute('SELECT * FROM analysis_sessions ORDER BY session_id DESC')
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_session_by_id(session_id):
    """Get a single session's full data for replay."""
    conn = get_db_connection()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM analysis_sessions WHERE session_id = ?', (session_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_daily_threat_counts():
    """Get daily threat counts and attack types for the Threat Calendar Heatmap.
    Returns: dict of {date_str: {'count': N, 'types': ['DoS', 'Recon', ...]}}
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DATE(timestamp) as day, COUNT(*) as count,
                   GROUP_CONCAT(DISTINCT attack_type) as types
            FROM attack_logs
            WHERE timestamp IS NOT NULL
            GROUP BY DATE(timestamp)
            ORDER BY day DESC
        ''')
        rows = cursor.fetchall()
        result = {}
        for row in rows:
            day_str = row[0]
            if day_str:
                result[day_str] = {
                    'count': row[1],
                    'types': row[2] if row[2] else ''
                }
        return result
    finally:
        conn.close()
