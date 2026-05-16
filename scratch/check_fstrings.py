import ast
from pathlib import Path

file_path = Path(r"c:\Users\ELZAHBIA\GRADUATION\ali_pro-main\network_intrusion_agent_v2\src\agent_app.py")
content = file_path.read_text(encoding="utf-8")

try:
    ast.parse(content)
    print("No SyntaxError found in agent_app.py")
except SyntaxError as e:
    print(f"SyntaxError found at line {e.lineno}: {e.msg}")
    # Print the problematic line
    lines = content.splitlines()
    if 0 < e.lineno <= len(lines):
        print(f"Line {e.lineno}: {lines[e.lineno-1]}")
except Exception as e:
    print(f"Error parsing file: {e}")
