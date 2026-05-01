import re

with open('c:/Users/ELZAHBIA/GRADUATION/ali_pro-main/network_intrusion_agent_v2/src/agent_app.py', 'r', encoding='utf-8') as f:
    code = f.read()

code = code.replace('{agent_action.strip().replace(\'        <\', \'<\')}', '{agent_action}')

def repl(m):
    return m.group(0).replace('            ', '').replace('        ', '')

code = re.sub(r'(agent_action\s*=\s*\"\"\")[\s\S]*?(\"\"\")', repl, code)

with open('c:/Users/ELZAHBIA/GRADUATION/ali_pro-main/network_intrusion_agent_v2/src/agent_app.py', 'w', encoding='utf-8') as f:
    f.write(code)
