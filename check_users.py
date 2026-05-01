import sqlite3
import os

DB_PATH = "data/iids_logs.db"

if os.path.exists(DB_PATH):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT email, full_name FROM users;")
        users = cursor.fetchall()
        print("Users found:")
        for u in users:
            print(f"- {u[0]} ({u[1]})")
    except Exception as e:
        print(f"Error reading users: {e}")
    finally:
        conn.close()
else:
    print("Database file not found.")
