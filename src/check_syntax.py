import ast
try:
    with open(r'c:\Users\ELZAHBIA\GRADUATION\ali_pro-main\network_intrusion_agent_v2\src\agent_app.py', 'r', encoding='utf-8') as f:
        source = f.read()
    ast.parse(source)
    print("No syntax errors found.")
except SyntaxError as e:
    print(f"SyntaxError: {e.msg} at line {e.lineno}, offset {e.offset}")
    # Print the line and a few around it
    lines = source.splitlines()
    start = max(0, e.lineno - 5)
    end = min(len(lines), e.lineno + 5)
    for i in range(start, end):
        prefix = "-> " if i + 1 == e.lineno else "   "
        print(f"{prefix}{i+1}: {lines[i]}")
except Exception as e:
    print(f"Error: {e}")
