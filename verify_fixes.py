import ast

files = [
    'src/agents.py',
    'src/anomaly.py',
    'src/database.py',
    'src/server.py',
    'src/scanners.py',
    'src/rl_engine.py',
    'src/payload_mutator.py',
    'src/xai.py',
    'src/models.py',
]

print('=== Syntax Check ===')
all_ok = True
for f in files:
    try:
        with open(f, encoding='utf-8') as fh:
            ast.parse(fh.read())
        print(f'  OK  {f}')
    except SyntaxError as e:
        print(f'  ERR {f}: {e}')
        all_ok = False

print()
print('=== Key Fix Checks ===')

with open('src/server.py', encoding='utf-8') as f: s = f.read()
print('  [1]  BG task owns Session:        ', 'Session(engine)' in s and 'process_scan_background' in s)
print('  [2]  lifespan (no on_event):      ', 'lifespan' in s and 'on_event' not in s)
print('  [10] [HARDENED] stripped:         ', 'replace(" [HARDENED]", "")' in s or ".replace(" in s and "HARDENED" in s)

with open('src/anomaly.py', encoding='utf-8') as f: s = f.read()
print('  [3]  has_anomaly flag:            ', 'has_anomaly' in s and 'any(True for _ in [])' not in s)

with open('src/agents.py', encoding='utf-8') as f: s = f.read()
print('  [4]  epochs always 2:             ', '"epochs":         2,' in s and '2 if status' not in s)
print('  [6]  LLM03 no len>300:            ', 'len(response) > 300' not in s)
print('  [8]  Epoch2 error logged:         ', 'Epoch 2 API error' in s)
print('  [15a] No AAAA artifact:           ', 'AAAA' not in s)
print('  [15b] f-string on LLM08 removed:  ', 'f"High temperature' not in s)

with open('requirements.txt', encoding='utf-8') as f: s = f.read()
print('  [5]  numpy version fixed:         ', '2.7.7' not in s and 'numpy' in s)
print('  [14] streamlit removed:           ', 'streamlit' not in s)
print('  [14] pandas removed:              ', 'pandas' not in s)
print('  [14] plotly removed:              ', 'plotly' not in s)

with open('src/database.py', encoding='utf-8') as f: s = f.read()
print('  [9]  DB path anchored:            ', '__file__' in s)

with open('src/scanners.py', encoding='utf-8') as f: s = f.read()
print('  [11] Specialist classes used:     ', 'InjectorAgent' in s and 'DoSAgent' in s)
print('  [12] generation_log snapshot:     ', 'list(mutator.generation_log)' in s)

with open('frontend/src/App.jsx', encoding='utf-8') as f: s = f.read()
print('  [13] Polling at 1500ms:           ', s.count('}, 1500);') >= 2)
print('  [16] No arrow over-match in regex:', 'PAYLOAD|' not in s and 'PAYLOAD' in s)

print()
if all_ok:
    print('All syntax checks PASSED.')
else:
    print('SYNTAX ERRORS FOUND — see above.')
