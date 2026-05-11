import sqlite3
import streamlit as st
import datetime
import hashlib
import os
from pathlib import Path
from geo_utils import get_ip_geolocation

try:
    import psycopg2
    from psycopg2.extras import DictCursor
except ImportError:
    psycopg2 = None
    DictCursor = None

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "iids_logs.db"

# ---- Dynamic Cloud Database Selection ----
DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
IS_POSTGRES = DATABASE_URL is not None and len(DATABASE_URL.strip()) > 0 and psycopg2 is not None

# Test the PostgreSQL connection on startup, fallback to SQLite if connection fails
if IS_POSTGRES:
    try:
        test_conn = psycopg2.connect(DATABASE_URL, connect_timeout=5)
        test_conn.close()
    except Exception as e:
        print(f"IIDS Warning: Cloud database connection failed ({e}). Falling back to local SQLite.")
        IS_POSTGRES = False


# ---- Unified Database Driver Wrappers ----

class UnifiedCursor:
    """A wrapper for database cursors to unify SQLite and PostgreSQL behaviors and queries."""
    def __init__(self, cursor, is_postgres=False, row_factory=None):
        self.cursor = cursor
        self.is_postgres = is_postgres
        self.row_factory = row_factory
        self._last_inserted_id = None

    @property
    def lastrowid(self):
        if self.is_postgres:
            return self._last_inserted_id
        return self.cursor.lastrowid

    def execute(self, query, params=None):
        if params is None:
            params = ()

        if self.is_postgres:
            # 1. Translate SQLite '?' parameter placeholders to PostgreSQL '%s'
            query = query.replace('?', '%s')
            
            # 2. Adapt SQLite PRIMARY KEY AUTOINCREMENT syntax to PostgreSQL
            query = query.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')
            
            # 3. Adapt Group Concat function
            if 'GROUP_CONCAT(DISTINCT attack_type)' in query:
                query = query.replace("GROUP_CONCAT(DISTINCT attack_type)", "string_agg(DISTINCT attack_type, ',')")
            elif 'GROUP_CONCAT' in query:
                query = query.replace("GROUP_CONCAT", "string_agg")
                
            # 4. Adapt SQLite INSERT OR REPLACE to PostgreSQL ON CONFLICT
            if 'INSERT OR REPLACE INTO blocked_ips' in query:
                query = """
                    INSERT INTO blocked_ips (ip, user_email, attack_type, date_added)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (ip, user_email) DO UPDATE SET
                        attack_type = EXCLUDED.attack_type,
                        date_added = EXCLUDED.date_added
                """

            # 5. Handle PostgreSQL returning inserted IDs for lastrowid simulation
            is_insert = query.strip().upper().startswith('INSERT')
            if is_insert:
                if 'attack_logs' in query and 'RETURNING id' not in query:
                    query += " RETURNING id"
                elif 'users' in query and 'RETURNING id' not in query:
                    query += " RETURNING id"
                elif 'analysis_sessions' in query and 'RETURNING session_id' not in query:
                    query += " RETURNING session_id"

            # Execute query on Postgres
            self.cursor.execute(query, params)
            
            # Retrieve RETURNING id for lastrowid
            if is_insert and ('RETURNING id' in query or 'RETURNING session_id' in query):
                try:
                    row = self.cursor.fetchone()
                    if row:
                        self._last_inserted_id = row[0]
                except Exception:
                    self._last_inserted_id = None
        else:
            # Execute query on SQLite
            self.cursor.execute(query, params)
            
        return self

    def fetchone(self):
        row = self.cursor.fetchone()
        if row is None:
            return None
        return row

    def fetchall(self):
        return self.cursor.fetchall()

    def close(self):
        self.cursor.close()

    def __iter__(self):
        return iter(self.cursor)

    def __getattr__(self, name):
        return getattr(self.cursor, name)


class UnifiedConnection:
    """A wrapper for database connections to unify SQLite and PostgreSQL behaviors."""
    def __init__(self, conn, is_postgres=False):
        self.conn = conn
        self.is_postgres = is_postgres
        self._row_factory = None

    @property
    def row_factory(self):
        return self._row_factory

    @row_factory.setter
    def row_factory(self, val):
        self._row_factory = val
        if not self.is_postgres:
            self.conn.row_factory = val

    def cursor(self):
        if self.is_postgres:
            # DictCursor mimics sqlite3.Row permitting dict conversion & named/index property retrieval
            return UnifiedCursor(self.conn.cursor(cursor_factory=DictCursor), True)
        else:
            return UnifiedCursor(self.conn.cursor(), False, self._row_factory)

    def commit(self):
        self.conn.commit()

    def rollback(self):
        try:
            self.conn.rollback()
        except Exception:
            pass

    def close(self):
        self.conn.close()

    def __getattr__(self, name):
        return getattr(self.conn, name)

    def execute(self, query, params=None):
        cur = self.cursor()
        cur.execute(query, params)
        return cur


def get_db_connection():
    """Create a thread-safe unified connection for either SQLite or cloud PostgreSQL."""
    if IS_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL)
        # Enable auto-commit for non-transaction queries if needed or standard connection wrapping
        return UnifiedConnection(conn, is_postgres=True)
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass
        return UnifiedConnection(conn, is_postgres=False)


# ---- Database Initialization & Migrations ----

def init_db():
    """Build and migrate table architectures safely for SQLite and PostgreSQL."""
    conn = get_db_connection()
    
    # Enable autocommit for PostgreSQL to execute schema migrations as separate transactions
    if conn.is_postgres:
        try:
            conn.conn.autocommit = True
        except Exception:
            pass
            
    cursor = conn.cursor()
    
    # 1. Migrate attack_logs schema safely
    try:
        cursor.execute("SELECT alert_sent FROM attack_logs LIMIT 1")
    except Exception:
        # If the check fails (e.g. column or table missing), drop the table so it can be re-created fresh
        try:
            cursor.execute("DROP TABLE IF EXISTS attack_logs")
        except Exception:
            pass
    
    # 2. Migrate analysis_sessions schema safely
    try:
        cursor.execute("SELECT attack_distribution FROM analysis_sessions LIMIT 1")
    except Exception:
        try:
            cursor.execute("ALTER TABLE analysis_sessions ADD COLUMN attack_distribution TEXT DEFAULT ''")
        except Exception:
            pass

    # 3. Create attack_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id SERIAL PRIMARY KEY,
            user_email TEXT,
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

    # Migrate attack_logs: add user_email column if missing
    try:
        cursor.execute("SELECT user_email FROM attack_logs LIMIT 1")
    except Exception:
        conn.rollback()
        cursor = conn.cursor()
        try:
            cursor.execute("ALTER TABLE attack_logs ADD COLUMN user_email TEXT")
        except Exception:
            pass

    # 4. Create blocked_ips table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT,
            user_email TEXT,
            attack_type TEXT,
            date_added TEXT,
            PRIMARY KEY (ip, user_email)
        )
    ''')

    # Migrate blocked_ips: add user_email column if missing
    try:
        cursor.execute("SELECT user_email FROM blocked_ips LIMIT 1")
    except Exception:
        conn.rollback()
        cursor = conn.cursor()
        try:
            cursor.execute("ALTER TABLE blocked_ips ADD COLUMN user_email TEXT")
        except Exception:
            pass

    # 5. Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
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
    except Exception:
        conn.rollback()
        cursor = conn.cursor()
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN profile_pic TEXT")
        except Exception:
            pass

    # Migrate users: add telegram columns if missing
    for _tg_col in ['telegram_bot_token', 'telegram_chat_id', 'telegram_enabled']:
        try:
            cursor.execute(f"SELECT {_tg_col} FROM users LIMIT 1")
        except Exception:
            conn.rollback()
            cursor = conn.cursor()
            try:
                _default = "0" if _tg_col == 'telegram_enabled' else "''"
                cursor.execute(f"ALTER TABLE users ADD COLUMN {_tg_col} TEXT DEFAULT {_default}")
            except Exception:
                pass

    # 6. Create analysis_sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_sessions (
            session_id SERIAL PRIMARY KEY,
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


# ---- Core Application Database Operations ----

def save_attack_to_db(alert, user_email=""):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        ts = alert.get('timestamp', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        src_ip = alert.get('src_ip', '')
        
        city, country, lat, lon = get_ip_geolocation(src_ip)
        
        if lat is None or lon is None or lat == 0 or lon == 0:
            from geo_utils import _get_mock_location
            city, country, lat, lon = _get_mock_location()
        
        cursor.execute('''
            INSERT INTO attack_logs (user_email, timestamp, src_ip, dst_ip, attack_type, severity, anomaly_score, malicious_probability, details, status, shap_explanation, city, country, latitude, longitude, alert_sent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_email,
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
            lon,
            alert.get('alert_sent', 0)
        ))
        
        alert_id = cursor.lastrowid
        conn.commit()
        
        alert['id'] = alert_id
        alert['city'] = city
        alert['country'] = country
        alert['latitude'] = lat
        alert['longitude'] = lon
        return alert_id
    finally:
        conn.close()


def get_all_logs(user_email="", limit=100):
    conn = get_db_connection()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if user_email:
            cursor.execute('SELECT * FROM attack_logs WHERE user_email = ? ORDER BY id DESC LIMIT ?', (user_email, limit))
        else:
            cursor.execute('SELECT * FROM attack_logs ORDER BY id DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_active_logs_count(user_email=""):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if user_email:
            cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE status='ACTIVE' AND user_email = ?", (user_email,))
        else:
            cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE status='ACTIVE'")
        return cursor.fetchone()[0]
    finally:
        conn.close()


def get_total_malicious_count(user_email=""):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if user_email:
            cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE user_email = ?", (user_email,))
        else:
            cursor.execute("SELECT COUNT(*) FROM attack_logs")
        return cursor.fetchone()[0]
    finally:
        conn.close()


def block_ip_db(ip, user_email="", attack_type="Manual Block"):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO blocked_ips (ip, user_email, attack_type, date_added)
            VALUES (?, ?, ?, ?)
        ''', (ip, user_email, attack_type, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    finally:
        conn.close()


def unblock_ip_db(ip, user_email=""):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM blocked_ips WHERE ip = ? AND user_email = ?', (ip, user_email))
        conn.commit()
    finally:
        conn.close()


def get_blocked_ips_db(user_email=""):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if user_email:
            cursor.execute('SELECT ip FROM blocked_ips WHERE user_email = ?', (user_email,))
        else:
            cursor.execute('SELECT ip FROM blocked_ips')
        rows = cursor.fetchall()
        return set(row[0] for row in rows)
    finally:
        conn.close()


def get_blocked_ips_detailed(user_email=""):
    conn = get_db_connection()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Subquery ordering is parameterized for standard and PG compatibility
        query = '''
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
                SELECT src_ip, user_email, attack_type, severity, latitude, longitude, city, country,
                       anomaly_score, malicious_probability,
                       ROW_NUMBER() OVER (PARTITION BY src_ip, user_email ORDER BY id DESC) AS rn
                FROM attack_logs
            ) a ON b.ip = a.src_ip AND b.user_email = a.user_email AND a.rn = 1
            LEFT JOIN (
                SELECT src_ip, user_email, COUNT(*) AS total_hits
                FROM attack_logs
                GROUP BY src_ip, user_email
            ) s ON b.ip = s.src_ip AND b.user_email = s.user_email
        '''
        if user_email:
            query += " WHERE b.user_email = ?"
            cursor.execute(query + " ORDER BY b.date_added DESC", (user_email,))
        else:
            cursor.execute(query + " ORDER BY b.date_added DESC")
            
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_normal_vs_attack_baseline(ip):
    conn = get_db_connection()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT anomaly_score, malicious_probability, attack_type, severity
            FROM attack_logs WHERE src_ip = ? ORDER BY id DESC LIMIT 1
        ''', (ip,))
        attack_row = cursor.fetchone()
        
        if not attack_row:
            return None
        
        attack_data = dict(attack_row)
        
        cursor.execute('''
            SELECT AVG(anomaly_score) as avg_anomaly,
                   MAX(malicious_probability) as max_prob,
                   COUNT(*) as hit_count
            FROM attack_logs WHERE src_ip = ?
        ''', (ip,))
        agg_row = cursor.fetchone()
        agg = dict(agg_row) if agg_row else {}
        
        normal_baselines = {
            'anomaly_score': 0.02,
            'malicious_probability': 0.05,
            'threat_level': 'NONE',
            'status': 'BENIGN',
        }
        
        attack_observed = {
            'anomaly_score': round(attack_data.get('anomaly_score', 0) or 0, 4),
            'malicious_probability': round(attack_data.get('malicious_probability', 0) or 0, 4),
            'threat_level': attack_data.get('severity', 'N/A'),
            'attack_type': attack_data.get('attack_type', 'Unknown'),
            'avg_anomaly': round(agg.get('avg_anomaly', 0) or 0, 4),
            'max_probability': round(agg.get('max_prob', 0) or 0, 4),
            'total_detections': agg.get('hit_count', 0) or 0,
        }
        
        return {
            'normal': normal_baselines,
            'attack': attack_observed,
        }
    finally:
        conn.close()


def get_attacker_profile(ip, user_email=""):
    conn = get_db_connection()
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if user_email:
            cursor.execute('''
                SELECT attack_type, severity, timestamp, dst_ip, anomaly_score, city, country, details
                FROM attack_logs WHERE src_ip = ? AND user_email = ? ORDER BY id DESC
            ''', (ip, user_email))
        else:
            cursor.execute('''
                SELECT attack_type, severity, timestamp, dst_ip, anomaly_score, city, country, details
                FROM attack_logs WHERE src_ip = ? ORDER BY id DESC
            ''', (ip,))
        rows = [dict(r) for r in cursor.fetchall()]
        
        if not rows:
            return None
        
        total_bytes = 0
        for r in rows:
            try:
                d = r.get('details', '')
                if 'B /' in d:
                    b_part = d.split(',')[-1].split('/')[0]
                    total_bytes += int(''.join(filter(str.isdigit, b_part)))
                elif "Auto-Log" in d:
                    total_bytes += 1.42 * 1024 * 1024
            except Exception:
                pass

        attack_types = list(set(r['attack_type'] for r in rows if r.get('attack_type')))
        total_hits = len(rows)
        severities = [r['severity'] for r in rows if r.get('severity')]
        countries = list(set(r['country'] for r in rows if r.get('country')))
        cities = list(set(r['city'] for r in rows if r.get('city')))
        
        if total_hits >= 10 or 'CRITICAL' in severities:
            risk = 'HIGH'
        elif total_hits >= 4 or 'HIGH' in severities:
            risk = 'MEDIUM'
        else:
            risk = 'LOW'
        
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
            'total_bytes': total_bytes,
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


def clear_db(user_email=""):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if user_email:
            cursor.execute('DELETE FROM attack_logs WHERE user_email = ?', (user_email,))
            cursor.execute('DELETE FROM blocked_ips WHERE user_email = ?', (user_email,))
        else:
            cursor.execute('DELETE FROM attack_logs')
            cursor.execute('DELETE FROM blocked_ips')
        conn.commit()
    finally:
        conn.close()


def clear_blocklist_db(user_email=""):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if user_email:
            cursor.execute('DELETE FROM blocked_ips WHERE user_email = ?', (user_email,))
        else:
            cursor.execute('DELETE FROM blocked_ips')
        conn.commit()
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
        conn.commit()
        return True, "Registration successful."
    except Exception as e:
        # Check SQLite vs PostgreSQL integrity error representation
        err_msg = str(e).lower()
        if 'unique' in err_msg or 'duplicate' in err_msg:
            return False, "Email already exists. Please login."
        return False, f"Error: {str(e)}"
    finally:
        conn.close()


def update_user_profile_pic(email, base64_img):
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


def save_telegram_settings(email, bot_token, chat_id, enabled):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET telegram_bot_token = ?, telegram_chat_id = ?, telegram_enabled = ? WHERE email = ?",
            (bot_token, chat_id, '1' if enabled else '0', email)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error saving Telegram settings: {e}")
        return False
    finally:
        conn.close()


def get_telegram_settings(email):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT telegram_bot_token, telegram_chat_id, telegram_enabled FROM users WHERE email = ?",
            (email,)
        )
        row = cursor.fetchone()
        if row:
            return {
                'bot_token': row[0] or '',
                'chat_id': row[1] or '',
                'enabled': row[2] == '1'
            }
        return {'bot_token': '', 'chat_id': '', 'enabled': False}
    except Exception:
        return {'bot_token': '', 'chat_id': '', 'enabled': False}
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
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_sessions(user_email=""):
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
