from pathlib import Path

file_path = Path(r"c:\Users\ELZAHBIA\GRADUATION\ali_pro-main\network_intrusion_agent_v2\src\agent_app.py")
content = file_path.read_text(encoding="utf-8")

# Remove the stray brace
content = content.replace('    /* Sidebar Toggle - Moved to Authenticated Section to prevent early appearance */\n \n    }', '    /* Sidebar Toggle - Moved to Authenticated Section to prevent early appearance */')

file_path.write_text(content, encoding="utf-8")
print("Fixed stray brace")
