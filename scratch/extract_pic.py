import sqlite3
import base64
import os
from pathlib import Path

# Paths
DB_PATH = Path("c:/Users/ELZAHBIA/GRADUATION/ali_pro-main/network_intrusion_agent_v2/data/iids_logs.db")
OUTPUT_DIR = Path("c:/Users/ELZAHBIA/GRADUATION/ali_pro-main/network_intrusion_agent_v2/data/profile_pics")
EMAIL = "nada.shaker@gmail.com"

def extract_profile_pic():
    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT profile_pic FROM users WHERE email = ?", (EMAIL,))
    row = cursor.fetchone()
    
    if row and row[0]:
        img_data = row[0]
        # Remove data:image/png;base64, prefix if present
        if "," in img_data:
            img_data = img_data.split(",")[1]
            
        try:
            img_bytes = base64.b64decode(img_data)
            output_path = OUTPUT_DIR / f"{EMAIL.replace('@', '_').replace('.', '_')}.png"
            
            with open(output_path, "wb") as f:
                f.write(img_bytes)
            
            print(f"Successfully extracted profile pic for {EMAIL} to {output_path}")
            return output_path
        except Exception as e:
            print(f"Error decoding image: {e}")
    else:
        print(f"No profile pic found for {EMAIL}")
    
    conn.close()

if __name__ == "__main__":
    extract_profile_pic()
