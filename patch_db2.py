import traceback

try:
    with open('src/db_utils.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    target = 'cursor.execute("SELECT latitude FROM attack_logs LIMIT 1")'
    replacement = 'cursor.execute("SELECT alert_sent FROM attack_logs LIMIT 1")'
    
    content = content.replace(target, replacement)
    
    with open('src/db_utils.py', 'w', encoding='utf-8') as f:
        f.write(content)
        
    import sys
    sys.path.append('src')
    from db_utils import init_db
    init_db()
    print('DB schema forced to migrate correctly.')
except Exception as e:
    traceback.print_exc()
