import traceback

try:
    with open('src/db_utils.py', 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Update schema
    target_schema = '''            city TEXT,
            country TEXT,
            latitude REAL,
            longitude REAL'''
    replacement_schema = '''            city TEXT,
            country TEXT,
            latitude REAL,
            longitude REAL,
            alert_sent INTEGER DEFAULT 0'''
    content = content.replace(target_schema, replacement_schema)
    
    # 2. Update insert statement
    target_insert = '''        cursor.execute("""
            INSERT INTO attack_logs (timestamp, src_ip, dst_ip, attack_type, severity, 
                                     anomaly_score, malicious_probability, details, status, shap_explanation, 
                                     city, country, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get('timestamp', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            alert.get('src_ip', 'Unknown'),
            alert.get('dst_ip', 'Unknown'),
            alert.get('attack_type', 'Unknown'),
            alert.get('severity', 'LOW'),
            alert.get('anomaly_score', 0.0),
            alert.get('malicious_probability', 0.0),
            alert.get('details', ''),
            alert.get('status', 'ACTIVE'),
            alert.get('shap_explanation', ''),
            city, country, lat, lon
        ))'''
        
    replacement_insert = '''        cursor.execute("""
            INSERT INTO attack_logs (timestamp, src_ip, dst_ip, attack_type, severity, 
                                     anomaly_score, malicious_probability, details, status, shap_explanation, 
                                     city, country, latitude, longitude, alert_sent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get('timestamp', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            alert.get('src_ip', 'Unknown'),
            alert.get('dst_ip', 'Unknown'),
            alert.get('attack_type', 'Unknown'),
            alert.get('severity', 'LOW'),
            alert.get('anomaly_score', 0.0),
            alert.get('malicious_probability', 0.0),
            alert.get('details', ''),
            alert.get('status', 'ACTIVE'),
            alert.get('shap_explanation', ''),
            city, country, lat, lon,
            alert.get('alert_sent', 0)
        ))'''
        
    content = content.replace(target_insert, replacement_insert)

    with open('src/db_utils.py', 'w', encoding='utf-8') as f:
        f.write(content)
        
    print("Database utils successfully patched.")
except Exception as e:
    traceback.print_exc()
