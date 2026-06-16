import sys
sys.path.insert(0, 'model')
from classify import DANGEROUS_FUNCTIONS, extract_features

code = "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
f = extract_features(code)
print('dangerous_fn_count:', f['dangerous_fn_count'])
for fn in DANGEROUS_FUNCTIONS:
    if fn in code.lower():
        print('DETECTADO:', fn)