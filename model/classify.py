#!/usr/bin/env python3
"""
classify.py — Clasificador de vulnerabilidades en código fuente
Proyecto Integrador Parcial II — Desarrollo de Software Seguro
Universidad de las Fuerzas Armadas ESPE

Uso:
    python classify.py --diff <archivo_diff> [--output json]
    python classify.py --code "print('hello')"
"""

import ast
import re
import sys
import json
import argparse
import numpy as np
from pathlib import Path
import requests # <-- Añadir al inicio del archivo
import os

MODEL_PATH = Path(__file__).parent / "vulnerability_model.pkl"
METADATA_PATH = Path(__file__).parent / "model_metadata.json"

DANGEROUS_FUNCTIONS = [
    'eval', 'exec', 'os.system', 'os.popen',
    'pickle.loads', 'yaml.load', '__import__',
    'compile', 'execfile', 'ctypes', 'marshal'
]

SANITIZATION_PATTERNS = [
    'escape', 'sanitize', 'validate', 'bleach',
    'html.escape', 'urllib.parse.quote', 'shlex.quote',
    'hashlib', 'hmac', 'secrets', 'bcrypt', 'argon2'
]

SQL_INJECTION_PATTERNS = [
    r'execute\s*\(\s*["\'].*\+',
    r'execute\s*\(\s*f["\']',
    r'SELECT.*\+\s*\w',
    r'INSERT.*\+\s*\w',
    r'UPDATE.*\+\s*\w',
    r'DELETE.*\+\s*\w',
]

COMMAND_INJECTION_PATTERNS = [
    r'os\.system\s*\(',
    r'subprocess\.call\s*\(.*shell\s*=\s*True',
    r'subprocess\.Popen\s*\(.*shell\s*=\s*True',
    r'os\.popen\s*\(',
]

XSS_PATTERNS = [
    r'innerHTML\s*=\s*\w',
    r'document\.write\s*\(',
    r'render_template_string\s*\(.*\+',
]

VULN_TYPES = {
    'sql_injection': 'CWE-89: SQL Injection',
    'cmd_injection': 'CWE-78: OS Command Injection',
    'xss': 'CWE-79: Cross-Site Scripting (XSS)',
    'hardcoded_secrets': 'CWE-798: Hardcoded Credentials',
    'insecure_deserialization': 'CWE-502: Insecure Deserialization',
    'path_traversal': 'CWE-22: Path Traversal',
    'dangerous_eval': 'CWE-95: Improper Code Generation (eval/exec)',
}


def get_ast_depth(code):
    try:
        tree = ast.parse(code)
        def depth(node):
            children = list(ast.iter_child_nodes(node))
            return 0 if not children else 1 + max(depth(c) for c in children)
        return depth(tree)
    except Exception:
        lines = code.split('\n')
        try:
            return max((len(l) - len(l.lstrip())) // 4 for l in lines if l.strip())
        except ValueError:
            return 0


def extract_features(code):
    code_lower = code.lower()
    lines = code.split('\n')
    f = {}

    f['num_lines'] = len(lines)
    f['num_tokens'] = len(code.split())
    f['avg_line_length'] = float(np.mean([len(l) for l in lines])) if lines else 0.0
    f['max_line_length'] = max((len(l) for l in lines), default=0)
    f['num_comments'] = sum(1 for l in lines if l.strip().startswith('#') or '//' in l)
    f['ast_depth'] = get_ast_depth(code)

    for fn in DANGEROUS_FUNCTIONS:
        pattern = r'\b' + re.escape(fn.split('.')[-1]) + r'\s*\('
        f[f'uses_{fn.replace(".", "_")}'] = int(bool(re.search(pattern, code_lower)))
    f['dangerous_fn_count'] = sum(f[f'uses_{fn.replace(".", "_")}'] for fn in DANGEROUS_FUNCTIONS)

    for s in SANITIZATION_PATTERNS:
        f[f'sanitizes_{s.replace(".", "_")}'] = int(s in code_lower)
    f['sanitization_count'] = sum(f[f'sanitizes_{s.replace(".", "_")}'] for s in SANITIZATION_PATTERNS)
    f['has_sanitization'] = int(f['sanitization_count'] > 0)

    f['sql_injection_patterns'] = sum(1 for p in SQL_INJECTION_PATTERNS if re.search(p, code, re.IGNORECASE))
    f['cmd_injection_patterns'] = sum(1 for p in COMMAND_INJECTION_PATTERNS if re.search(p, code))
    f['xss_patterns'] = sum(1 for p in XSS_PATTERNS if re.search(p, code, re.IGNORECASE))

    secret_patterns = [
        r'password\s*=\s*["\'][^"\']{4,}["\']',
        r'secret\s*=\s*["\'][^"\']{4,}["\']',
        r'api_key\s*=\s*["\'][^"\']{4,}["\']',
        r'token\s*=\s*["\'][^"\']{4,}["\']',
    ]
    f['hardcoded_secrets'] = sum(1 for p in secret_patterns if re.search(p, code, re.IGNORECASE))

    f['has_try_except'] = int('try:' in code or 'try {' in code)
    f['bare_except'] = int(bool(re.search(r'except\s*:', code)))
    f['has_finally'] = int('finally:' in code or 'finally {' in code)
    f['uses_env_vars'] = int('os.environ' in code or 'process.env' in code or 'getenv' in code)
    f['uses_parameterized'] = int(bool(re.search(r'execute\s*\([^)]+,\s*[\(\[]', code)))
    f['uses_orm'] = int('filter_by' in code or 'filter(' in code or '.query.' in code)
    f['uses_prepared'] = int('prepare(' in code_lower or ':id' in code or '= ?' in code or 'text(' in code)
    f['is_safe_sql'] = int(f['uses_parameterized'] > 0 or f['uses_orm'] > 0 or f['uses_prepared'] > 0)

    total = f['sql_injection_patterns'] + f['cmd_injection_patterns'] + f['xss_patterns'] + f['dangerous_fn_count']
    f['danger_sanitize_ratio'] = total / max(f['sanitization_count'] + 1, 1)

    return f


def detect_vulnerability_types(code):
    found = []
    code_lower = code.lower()

    if any(re.search(p, code, re.IGNORECASE) for p in SQL_INJECTION_PATTERNS):
        found.append(VULN_TYPES['sql_injection'])
    if any(re.search(p, code) for p in COMMAND_INJECTION_PATTERNS):
        found.append(VULN_TYPES['cmd_injection'])
    if any(re.search(p, code, re.IGNORECASE) for p in XSS_PATTERNS):
        found.append(VULN_TYPES['xss'])
    if re.search(r'(password|secret|api_key|token)\s*=\s*["\'][^"\']{4,}["\']', code, re.IGNORECASE):
        found.append(VULN_TYPES['hardcoded_secrets'])
    if 'pickle.loads' in code_lower or 'yaml.load(' in code_lower:
        found.append(VULN_TYPES['insecure_deserialization'])
    if re.search(r'open\s*\(.*\+', code):
        found.append(VULN_TYPES['path_traversal'])
    if re.search(r'\beval\s*\(|\bexec\s*\(', code):
        found.append(VULN_TYPES['dangerous_eval'])

    return found


def parse_diff(diff_content):
    added_lines = []
    for line in diff_content.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            added_lines.append(line[1:])
    return '\n'.join(added_lines)


def classify(code):
    try:
        import joblib
        model = joblib.load(MODEL_PATH)
        with open(METADATA_PATH) as f:
            meta = json.load(f)
        feature_names = meta['feature_names']
    except FileNotFoundError:
        print("[ERROR] Modelo no encontrado. Ejecuta model/train.py primero.", file=sys.stderr)
        sys.exit(1)

    features = extract_features(code)
    X = np.array([[features.get(f, 0) for f in feature_names]])

    proba = model.predict_proba(X)[0]
    pred = model.predict(X)[0]
    vuln_types = detect_vulnerability_types(code)

    label = 'VULNERABLE' if pred == 1 else 'SEGURO'

    return {
        'prediction': label,
        'is_vulnerable': bool(pred == 1),
        'vulnerability_probability': float(proba[1]),
        'security_probability': float(proba[0]),
        'confidence': float(proba[pred]),
        'vulnerability_types': vuln_types,
        'features_summary': {
            'dangerous_functions': int(features['dangerous_fn_count']),
            'sanitization_present': bool(features['has_sanitization']),
            'sql_injection_patterns': int(features['sql_injection_patterns']),
            'command_injection_patterns': int(features['cmd_injection_patterns']),
            'xss_patterns': int(features['xss_patterns']),
            'hardcoded_secrets': int(features['hardcoded_secrets']),
            'ast_depth': int(features['ast_depth']),
        }
    }


def format_pr_comment(result):
    emoji = '🔴' if result['is_vulnerable'] else '🟢'
    label = result['prediction']
    prob = result['vulnerability_probability']
    conf = result['confidence']

    lines = [
        f"## {emoji} Resultado del Análisis de Seguridad: **{label}**",
        "",
        f"| Métrica | Valor |",
        f"|---------|-------|",
        f"| Predicción | `{label}` |",
        f"| Probabilidad de vulnerabilidad | `{prob:.2%}` |",
        f"| Confianza del modelo | `{conf:.2%}` |",
        f"| Funciones peligrosas detectadas | `{result['features_summary']['dangerous_functions']}` |",
        f"| Sanitización presente | `{'✅ Sí' if result['features_summary']['sanitization_present'] else '❌ No'}` |",
        "",
    ]

    if result['is_vulnerable']:
        lines.append("### ⚠️ Vulnerabilidades Detectadas")
        if result['vulnerability_types']:
            for vt in result['vulnerability_types']:
                lines.append(f"- {vt}")
        else:
            lines.append("- Patrón de código inseguro detectado por el modelo")
        lines.extend([
            "",
            "### 🔧 Acción Requerida",
            "Este PR ha sido **bloqueado automáticamente**. Por favor:",
            "1. Revisa el código en busca de las vulnerabilidades listadas arriba",
            "2. Aplica los parches necesarios",
            "3. Abre un nuevo PR con el código corregido",
            "",
            "> *Análisis realizado por el modelo Random Forest (Minería de Datos)*",
        ])
    else:
        lines.extend([
            "### ✅ El código pasó el análisis de seguridad",
            "El pipeline continuará automáticamente con las pruebas unitarias.",
            "",
            "> *Análisis realizado por el modelo Random Forest (Minería de Datos)*",
        ])

    return '\n'.join(lines)


def format_telegram_message(result, pr_info=None):
    emoji = '🔴 VULNERABLE' if result['is_vulnerable'] else '🟢 SEGURO'
    prob = result['vulnerability_probability']

    lines = [
        f"*Análisis de Seguridad — Pipeline CI/CD*",
        f"",
        f"*Resultado:* {emoji}",
        f"*Confianza:* {result['confidence']:.1%}",
        f"*P(Vulnerable):* {prob:.1%}",
    ]

    if pr_info:
        lines.extend([
            f"",
            f"*Repositorio:* `{pr_info.get('repo', 'N/A')}`",
            f"*PR:* #{pr_info.get('pr_number', 'N/A')} — {pr_info.get('pr_title', '')}",
            f"*Autor:* @{pr_info.get('author', 'N/A')}",
        ])

    if result['is_vulnerable'] and result['vulnerability_types']:
        lines.extend([f"", f"*Vulnerabilidades detectadas:*"])
        for vt in result['vulnerability_types']:
            lines.append(f"  • {vt}")
        lines.append(f"")
        lines.append(f"El merge ha sido bloqueado. Se requiere corrección.")
    else:
        lines.append(f"")
        lines.append(f"El código continuará al siguiente stage del pipeline.")

    return '\n'.join(lines)


def send_telegram_alert(message_text):
    import os
    import requests
    
    bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
    chat_id = os.environ.get('TELEGRAM_CHAT_ID')
    
    if not bot_token or not chat_id:
        print("[AVISO] Credenciales de Telegram no configuradas en variables de entorno.")
        return

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message_text,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, json=payload)
    except Exception as e:
        print(f"[ERROR] enviando Telegram: {e}")


def main():
    parser = argparse.ArgumentParser(description='Clasificador de vulnerabilidades')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--diff', help='Archivo .diff del PR')
    group.add_argument('--code', help='Código fuente como string')
    group.add_argument('--file', help='Archivo de código fuente')
    parser.add_argument('--output', choices=['json', 'comment', 'telegram'], default='json')
    parser.add_argument('--pr-repo', default='')
    parser.add_argument('--pr-number', default='')
    parser.add_argument('--pr-title', default='')
    parser.add_argument('--pr-author', default='')
    args = parser.parse_args()

    if args.diff:
        with open(args.diff) as f:
            diff_content = f.read()
        code = parse_diff(diff_content)
    elif args.file:
        with open(args.file) as f:
            code = f.read()
    else:
        code = args.code

    if not code.strip():
        print(json.dumps({'prediction': 'SEGURO', 'is_vulnerable': False,
                          'confidence': 1.0, 'vulnerability_probability': 0.0,
                          'note': 'Sin código para analizar'}))
        sys.exit(0)

    result = classify(code)

    if args.output == 'json':
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.output == 'comment':
        print(format_pr_comment(result))
    elif args.output == 'telegram':
        pr_info = {
            'repo': args.pr_repo,
            'pr_number': args.pr_number,
            'pr_title': args.pr_title,
            'author': args.pr_author,
        }
        mensaje = format_telegram_message(result, pr_info)
        print(mensaje) # Se imprime en la consola para los logs de GitHub
        send_telegram_alert(mensaje) # Hace la petición HTTP real a Telegram

    sys.exit(1 if result['is_vulnerable'] else 0)


if __name__ == '__main__':
    main()