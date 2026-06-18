#!/usr/bin/env python3
"""
scanner.py — Analizador de seguridad multi-archivo
Combina modelo ML (Random Forest) + Bandit (análisis estático)
para detección exhaustiva de vulnerabilidades en código Python.

Uso:
    python model/scanner.py --files app/login.py app/utils.py --output json
    python model/scanner.py --files-from /tmp/files.txt --output json > /tmp/result.json
    python model/scanner.py --from-result /tmp/result.json --output telegram
    python model/scanner.py --from-result /tmp/result.json --output email
"""

import os
import sys
import json
import subprocess
import argparse
import smtplib
import urllib.request
import urllib.parse
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

sys.path.insert(0, str(Path(__file__).parent))
from classify import classify as ml_classify, detect_vulnerability_types

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}

BANDIT_CWE_MAP = {
    "B102": "CWE-78",   "B103": "CWE-732", "B104": "CWE-605", "B105": "CWE-259",
    "B106": "CWE-259",  "B107": "CWE-259", "B108": "CWE-377", "B110": "CWE-391",
    "B201": "CWE-94",   "B301": "CWE-502", "B302": "CWE-502", "B303": "CWE-327",
    "B304": "CWE-327",  "B305": "CWE-327", "B307": "CWE-78",  "B308": "CWE-79",
    "B310": "CWE-601",  "B311": "CWE-330", "B312": "CWE-319", "B323": "CWE-295",
    "B324": "CWE-327",  "B325": "CWE-338", "B401": "CWE-319", "B402": "CWE-319",
    "B501": "CWE-295",  "B502": "CWE-295", "B505": "CWE-326", "B506": "CWE-20",
    "B507": "CWE-295",  "B601": "CWE-78",  "B602": "CWE-78",  "B603": "CWE-78",
    "B604": "CWE-78",   "B605": "CWE-78",  "B606": "CWE-78",  "B607": "CWE-78",
    "B608": "CWE-89",   "B609": "CWE-78",  "B610": "CWE-89",  "B611": "CWE-89",
    "B701": "CWE-134",  "B702": "CWE-79",  "B703": "CWE-79",
}

VULN_DISPLAY_NAMES = {
    "CWE-89":  "SQL Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-259": "Hardcoded Password/Credential",
    "CWE-798": "Hardcoded Credentials",
    "CWE-502": "Insecure Deserialization",
    "CWE-22":  "Path Traversal",
    "CWE-95":  "Code Injection (eval/exec)",
    "CWE-327": "Weak Cryptographic Algorithm",
    "CWE-330": "Weak Random Number Generator",
    "CWE-295": "Improper Certificate Validation",
    "CWE-94":  "Code Injection",
    "CWE-134": "Uncontrolled Format String",
    "CWE-601": "Open Redirect",
    "CWE-326": "Weak Encryption Key",
    "CWE-338": "Weak PRNG",
    "CWE-732": "Insecure File Permissions",
    "CWE-377": "Insecure Temp File",
    "CWE-391": "Unchecked Error Condition",
    "CWE-20":  "Improper Input Validation",
    "CWE-319": "Cleartext Transmission",
    "CWE-605": "Binding to All Interfaces",
}


def run_bandit(files):
    if not files:
        return {"results": [], "errors": {}, "metrics": {}}
    cmd = ["bandit", "-f", "json", "-ll", "--"] + list(files)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return {"results": [], "errors": {}, "metrics": {}}


def run_ml_on_file(filepath):
    try:
        code = Path(filepath).read_text(encoding="utf-8", errors="replace")
        if not code.strip():
            return None
        return ml_classify(code)
    except Exception as e:
        print(f"[ML] Error en {filepath}: {e}", file=sys.stderr)
        return None


def _normalize(path):
    return os.path.normpath(str(path))


def _bandit_cwe(issue):
    cwe_obj = issue.get("issue_cwe")
    if cwe_obj and isinstance(cwe_obj, dict):
        cid = cwe_obj.get("id")
        if cid:
            return f"CWE-{cid}"
    test_id = issue.get("test_id", "")
    return BANDIT_CWE_MAP.get(test_id, "")


def scan_files(files):
    files = [f for f in files if Path(f).is_file()]
    if not files:
        return _empty_result(files)

    bandit_data = run_bandit(files)
    bandit_by_file = {}
    for issue in bandit_data.get("results", []):
        key = _normalize(issue.get("filename", ""))
        bandit_by_file.setdefault(key, []).append(issue)

    results_per_file = {}
    all_vulns = []
    any_vulnerable = False

    for filepath in files:
        norm = _normalize(filepath)
        file_result = {
            "file": filepath,
            "is_vulnerable": False,
            "max_severity": "NONE",
            "ml_probability": 0.0,
            "vulnerabilities": [],
        }

        vuln_list = []

        for issue in bandit_by_file.get(norm, []):
            sev = issue.get("issue_severity", "LOW")
            conf = issue.get("issue_confidence", "LOW")
            if sev == "LOW" and conf == "LOW":
                continue

            test_id = issue.get("test_id", "")
            cwe = _bandit_cwe(issue)
            display = VULN_DISPLAY_NAMES.get(cwe, issue.get("test_name", "Vulnerability"))
            code_snippet = issue.get("code", "").strip()
            if len(code_snippet) > 120:
                code_snippet = code_snippet[:120] + "..."

            vuln_list.append({
                "source": "Bandit",
                "test_id": test_id,
                "cwe": cwe,
                "type": display,
                "description": issue.get("issue_text", ""),
                "severity": sev,
                "confidence": conf,
                "line": issue.get("line_number", 0),
                "code": code_snippet,
            })

        ml = run_ml_on_file(filepath)
        if ml:
            file_result["ml_probability"] = ml.get("vulnerability_probability", 0.0)
            if ml.get("is_vulnerable"):
                for vt in ml.get("vulnerability_types", []):
                    cwe_part = vt.split(":")[0].strip()
                    if not any(v["cwe"] == cwe_part for v in vuln_list):
                        type_part = vt.split(": ", 1)[1] if ": " in vt else vt
                        vuln_list.append({
                            "source": "ML-Model",
                            "test_id": "",
                            "cwe": cwe_part,
                            "type": type_part,
                            "description": f"Patrón inseguro detectado (confianza: {ml['confidence']:.0%})",
                            "severity": "HIGH",
                            "confidence": f"{ml['confidence']:.0%}",
                            "line": 0,
                            "code": "",
                        })

        vuln_list.sort(key=lambda v: SEVERITY_ORDER.get(v["severity"], 99))
        file_result["vulnerabilities"] = vuln_list

        if vuln_list:
            file_result["is_vulnerable"] = True
            any_vulnerable = True
            top_sev = vuln_list[0]["severity"]
            file_result["max_severity"] = top_sev

        results_per_file[filepath] = file_result
        all_vulns.extend(vuln_list)

    return {
        "is_vulnerable": any_vulnerable,
        "total_vulnerabilities": len(all_vulns),
        "vulnerable_files": [f for f, r in results_per_file.items() if r["is_vulnerable"]],
        "scanned_files": files,
        "results_per_file": results_per_file,
        "summary": {
            "high": sum(1 for v in all_vulns if v["severity"] == "HIGH"),
            "medium": sum(1 for v in all_vulns if v["severity"] == "MEDIUM"),
            "low": sum(1 for v in all_vulns if v["severity"] == "LOW"),
            "total": len(all_vulns),
        },
    }


def _empty_result(files):
    return {
        "is_vulnerable": False,
        "total_vulnerabilities": 0,
        "vulnerable_files": [],
        "scanned_files": list(files),
        "results_per_file": {},
        "summary": {"high": 0, "medium": 0, "low": 0, "total": 0},
        "note": "No se encontraron archivos Python válidos para analizar",
    }


def _escape_md(text):
    for ch in ['_', '[', ']', '(', ')']:
        text = text.replace(ch, '\\' + ch)
    return text


def format_telegram(result, pr_info=None):
    is_vuln = result["is_vulnerable"]
    summary = result["summary"]
    status = "VULNERABLE — MERGE BLOQUEADO" if is_vuln else "CÓDIGO SEGURO — PIPELINE APROBADO"
    header = "🔴" if is_vuln else "🟢"
    block_icon = "⛔" if is_vuln else "✅"

    lines = [
        f"{header} *PIPELINE DE SEGURIDAD CI/CD*",
        f"{block_icon} *{status}*",
        "",
    ]

    if pr_info and pr_info.get("pr_number"):
        repo = pr_info.get("repo", "")
        pr_num = pr_info.get("pr_number", "")
        author = pr_info.get("author", "")
        base = pr_info.get("base_ref", "")
        head = pr_info.get("head_ref", "")
        title = pr_info.get("pr_title", "")[:60]

        lines += [
            f"*Repo:* `{repo}`",
            f"*PR \\#{pr_num}:* {title}",
            f"*Autor:* @{author}",
            f"*Rama:* `{head}` → `{base}`",
            "",
        ]

    lines += [
        f"*Archivos analizados:* {len(result['scanned_files'])}",
        f"*Archivos con vulnerabilidades:* {len(result['vulnerable_files'])}",
    ]

    if is_vuln:
        lines += [
            f"*Total vulnerabilidades:* {summary['total']}",
            f"  • {SEVERITY_EMOJI['HIGH']} Alta: {summary['high']}",
            f"  • {SEVERITY_EMOJI['MEDIUM']} Media: {summary['medium']}",
            f"  • {SEVERITY_EMOJI['LOW']} Baja: {summary['low']}",
            "",
            "━━━━━━━━━━━━━━━━━━━",
            "*DETALLE POR ARCHIVO:*",
        ]

        char_count = sum(len(l) for l in lines)
        for filepath, fres in result["results_per_file"].items():
            if not fres["is_vulnerable"]:
                continue
            fname = os.path.basename(filepath)
            file_block = [f"\n📁 *{fname}*"]
            for v in fres["vulnerabilities"]:
                sem = SEVERITY_EMOJI.get(v["severity"], "⚪")
                cwe = f"`{v['cwe']}`" if v["cwe"] else ""
                line_str = f"  📍 Línea {v['line']}" if v["line"] > 0 else ""
                entry = f"  {sem} [{v['severity']}] {cwe} {v['type']}"
                if v.get("description"):
                    entry += f"\n     _{v['description'][:80]}_"
                if line_str:
                    entry += f"\n{line_str}"
                if v.get("code") and v["line"] > 0:
                    snippet = v["code"].replace('\n', ' ').strip()[:80]
                    entry += f"\n     `{snippet}`"
                file_block.append(entry)
            block_text = "\n".join(file_block)
            char_count += len(block_text)
            if char_count > 3800:
                lines.append("\n_... (ver detalles completos en el comentario del PR)_")
                break
            lines.append(block_text)

        lines += [
            "",
            "━━━━━━━━━━━━━━━━━━━",
            "⚠️ _El merge ha sido bloqueado automáticamente._",
            "_Corrija las vulnerabilidades y abra un nuevo PR._",
        ]
    else:
        lines += [
            "",
            "✅ _Todos los archivos pasaron el análisis de seguridad._",
            "_El pipeline continuará con las pruebas unitarias._",
        ]

    return "\n".join(lines)


def format_telegram_tests(outcome, pr_info=None):
    icon = "✅" if outcome == "success" else "❌"
    status = "PASARON TODAS LAS PRUEBAS" if outcome == "success" else "PRUEBAS FALLIDAS"
    pr_num = pr_info.get("pr_number", "") if pr_info else ""
    return f"{icon} *Pruebas Unitarias — {status}*\n\nPR \\#{pr_num}" if pr_num else f"{icon} *Pruebas Unitarias — {status}*"


def format_telegram_deploy(app_url, pr_info=None):
    pr_num = pr_info.get("pr_number", "") if pr_info else ""
    return f"🚀 *Deploy Exitoso en Producción*\n\nPR \\#{pr_num}\n🌐 {app_url}" if pr_num else f"🚀 *Deploy Exitoso en Producción*\n\n🌐 {app_url}"


def format_pr_comment(result):
    is_vuln = result["is_vulnerable"]
    summary = result["summary"]
    emoji = "🔴" if is_vuln else "🟢"
    status = "VULNERABLE" if is_vuln else "SEGURO"

    lines = [
        f"## {emoji} Resultado del Análisis de Seguridad: **{status}**",
        "",
        "### Resumen General",
        "",
        "| Métrica | Valor |",
        "|---------|-------|",
        f"| Archivos analizados | `{len(result['scanned_files'])}` |",
        f"| Archivos con vulnerabilidades | `{len(result['vulnerable_files'])}` |",
        f"| 🔴 Alta severidad | `{summary['high']}` |",
        f"| 🟡 Media severidad | `{summary['medium']}` |",
        f"| 🟢 Baja severidad | `{summary['low']}` |",
        f"| **Total vulnerabilidades** | **`{summary['total']}`** |",
        "",
    ]

    if is_vuln:
        lines += ["### ⚠️ Vulnerabilidades Detectadas por Archivo", ""]

        for filepath, fres in result["results_per_file"].items():
            if not fres["is_vulnerable"]:
                continue
            prob = fres.get("ml_probability", 0)
            lines += [
                f"#### 📁 `{filepath}`",
                f"**Probabilidad ML:** `{prob:.1%}` | **Severidad máxima:** `{fres['max_severity']}`",
                "",
                "| Severidad | Tipo de Vulnerabilidad | CWE | Línea | Fuente | Descripción |",
                "|-----------|------------------------|-----|-------|--------|-------------|",
            ]
            for v in fres["vulnerabilities"]:
                sem = SEVERITY_EMOJI.get(v["severity"], "⚪")
                line_str = str(v["line"]) if v["line"] > 0 else "—"
                cwe = f"`{v['cwe']}`" if v["cwe"] else "—"
                desc = (v.get("description") or "")[:100]
                lines.append(
                    f"| {sem} `{v['severity']}` | **{v['type']}** | {cwe} | {line_str} | {v['source']} | {desc} |"
                )

            vuln_with_code = [v for v in fres["vulnerabilities"] if v.get("code") and v["line"] > 0]
            if vuln_with_code:
                lines += ["", "<details><summary>📋 Ver fragmentos de código vulnerable</summary>", ""]
                for v in vuln_with_code[:5]:
                    lines += [
                        f"**Línea {v['line']} — {v['type']}** (`{v['cwe']}`)",
                        "```python",
                        v["code"],
                        "```",
                        "",
                    ]
                lines.append("</details>")

            lines.append("")

        lines += [
            "### 🔧 Acción Requerida",
            "",
            "Este PR ha sido **bloqueado automáticamente**. Para resolver:",
            "1. Revisa cada vulnerabilidad en la línea indicada",
            "2. Consulta el CWE correspondiente para la corrección adecuada",
            "3. Aplica la corrección y abre un nuevo PR",
            "",
            "> *Análisis realizado por: Modelo ML Random Forest + Bandit (Análisis Estático)*",
            "> *Universidad de las Fuerzas Armadas ESPE — Desarrollo de Software Seguro*",
        ]
    else:
        scanned = ", ".join(f"`{os.path.basename(f)}`" for f in result["scanned_files"]) or "—"
        lines += [
            "### ✅ El código pasó el análisis de seguridad",
            "",
            f"Archivos analizados: {scanned}",
            "",
            "Todos los archivos están libres de vulnerabilidades conocidas.",
            "El pipeline continuará automáticamente con las pruebas unitarias.",
            "",
            "> *Análisis: Modelo ML Random Forest + Bandit (Análisis Estático)*",
        ]

    return "\n".join(lines)


def format_email_html(result, pr_info=None):
    is_vuln = result["is_vulnerable"]
    summary = result["summary"]
    status = "VULNERABLE" if is_vuln else "SEGURO"
    accent = "#cc0000" if is_vuln else "#007733"
    banner_bg = "#fff0f0" if is_vuln else "#f0fff4"

    pr_rows = ""
    if pr_info:
        for label, key in [
            ("Repositorio", "repo"), ("PR #", "pr_number"),
            ("Título", "pr_title"), ("Autor", "author"),
            ("Rama origen", "head_ref"), ("Rama destino", "base_ref"),
        ]:
            val = pr_info.get(key, "—")
            if val:
                pr_rows += f"<tr><td style='font-weight:bold;width:160px'>{label}</td><td>{val}</td></tr>\n"

    vuln_rows = ""
    for filepath, fres in result["results_per_file"].items():
        if not fres["is_vulnerable"]:
            continue
        vuln_rows += f"""
<tr>
  <td colspan="6" style="background:#f5f5f5;font-weight:bold;padding:10px 8px">
    📁 {filepath} &nbsp;
    <span style="color:{accent}">({len(fres['vulnerabilities'])} vulnerabilidad(es))</span>
  </td>
</tr>"""
        for v in fres["vulnerabilities"]:
            sev_colors = {"HIGH": "#cc0000", "MEDIUM": "#e67e00", "LOW": "#888800"}
            sev_c = sev_colors.get(v["severity"], "#555")
            sev_bg = {"HIGH": "#fff0f0", "MEDIUM": "#fff8f0", "LOW": "#fffff0"}.get(v["severity"], "#fff")
            ln = str(v["line"]) if v["line"] > 0 else "—"
            code_cell = f"<code style='font-size:11px'>{v['code'][:100]}</code>" if v.get("code") else "—"
            vuln_rows += f"""
<tr style="background:{sev_bg}">
  <td style="color:{sev_c};font-weight:bold;text-align:center">{v['severity']}</td>
  <td><strong>{v['type']}</strong></td>
  <td style="font-family:monospace">{v.get('cwe','—')}</td>
  <td style="text-align:center">{ln}</td>
  <td style="color:#666;font-size:12px">{v['source']}</td>
  <td style="font-size:12px">{v.get('description','')[:120]}</td>
</tr>"""
        if fres.get("ml_probability", 0) > 0:
            vuln_rows += f"""
<tr style="background:#f9f9f9;border-top:1px solid #ddd">
  <td colspan="6" style="font-size:11px;color:#666;padding:4px 8px">
    🤖 ML Probability: <strong>{fres['ml_probability']:.1%}</strong>
  </td>
</tr>"""

    vuln_section = ""
    if is_vuln:
        vuln_section = f"""
<h2 style="color:{accent}">Vulnerabilidades Detectadas</h2>
<table border="0" cellpadding="8" cellspacing="0"
       style="border-collapse:collapse;width:100%;border:1px solid #ddd;font-size:13px">
  <thead>
    <tr style="background:{accent};color:white">
      <th style="width:90px">Severidad</th>
      <th>Tipo de Vulnerabilidad</th>
      <th style="width:90px">CWE</th>
      <th style="width:60px">Línea</th>
      <th style="width:90px">Fuente</th>
      <th>Descripción</th>
    </tr>
  </thead>
  <tbody>{vuln_rows}</tbody>
</table>
<div style="margin-top:20px;padding:15px;background:#fff3cd;border-left:4px solid #ffc107;border-radius:4px">
  <strong>⛔ Acción Requerida:</strong> Este PR ha sido bloqueado automáticamente.
  Corrija las vulnerabilidades indicadas y abra un nuevo PR.
</div>"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Análisis de Seguridad — {status}</title>
</head>
<body style="font-family:Arial,sans-serif;max-width:950px;margin:0 auto;padding:20px;color:#333">

  <div style="background:{banner_bg};border:2px solid {accent};border-radius:8px;
              padding:25px;text-align:center;margin-bottom:25px">
    <h1 style="color:{accent};margin:0 0 8px">
      {'🔴' if is_vuln else '🟢'} Pipeline de Seguridad CI/CD
    </h1>
    <h2 style="margin:0;color:{accent}">Resultado: {status}</h2>
  </div>

  <h2>Información del Análisis</h2>
  <table border="0" cellpadding="7" cellspacing="0"
         style="border-collapse:collapse;width:100%;border:1px solid #ddd">
    {pr_rows}
    <tr style="background:#f5f5f5">
      <td style="font-weight:bold;width:160px">Archivos analizados</td>
      <td>{len(result['scanned_files'])}</td>
    </tr>
    <tr>
      <td style="font-weight:bold">Archivos vulnerables</td>
      <td style="color:{accent if is_vuln else '#007733'}">{len(result['vulnerable_files'])}</td>
    </tr>
    <tr style="background:#f5f5f5">
      <td style="font-weight:bold">🔴 Alta severidad</td>
      <td style="color:#cc0000"><strong>{summary['high']}</strong></td>
    </tr>
    <tr>
      <td style="font-weight:bold">🟡 Media severidad</td>
      <td style="color:#e67e00"><strong>{summary['medium']}</strong></td>
    </tr>
    <tr style="background:#f5f5f5">
      <td style="font-weight:bold">🟢 Baja severidad</td>
      <td style="color:#888800"><strong>{summary['low']}</strong></td>
    </tr>
    <tr>
      <td style="font-weight:bold;font-size:15px">TOTAL</td>
      <td style="color:{accent};font-size:15px"><strong>{summary['total']}</strong></td>
    </tr>
  </table>

  {vuln_section}

  <hr style="margin:30px 0;border:none;border-top:1px solid #eee">
  <p style="color:#999;font-size:11px;text-align:center">
    Análisis realizado por: Modelo ML (Random Forest) + Bandit (Análisis Estático)<br>
    Universidad de las Fuerzas Armadas ESPE — Desarrollo de Software Seguro
  </p>
</body>
</html>"""


def send_telegram(message, bot_token, chat_id):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
    }).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"[ERROR] Telegram: {e}", file=sys.stderr)
        return None


def send_email(subject, html_body, smtp_server, smtp_port, email_from, email_to, email_password):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = email_from
    msg["To"] = email_to
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    try:
        with smtplib.SMTP(smtp_server, int(smtp_port), timeout=30) as srv:
            srv.ehlo()
            srv.starttls()
            srv.ehlo()
            srv.login(email_from, email_password)
            srv.sendmail(email_from, email_to.split(","), msg.as_string())
        print(f"[OK] Email enviado a: {email_to}")
        return True
    except Exception as e:
        print(f"[ERROR] Email: {e}", file=sys.stderr)
        return False


def _pr_info_from_env():
    return {
        "repo": os.environ.get("PR_REPO", ""),
        "pr_number": os.environ.get("PR_NUMBER", ""),
        "pr_title": os.environ.get("PR_TITLE", ""),
        "author": os.environ.get("PR_AUTHOR", ""),
        "base_ref": os.environ.get("PR_BASE_REF", ""),
        "head_ref": os.environ.get("PR_HEAD_REF", ""),
    }


def main():
    parser = argparse.ArgumentParser(description="Escáner de seguridad multi-archivo (ML + Bandit)")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--files", nargs="+", help="Archivos Python a escanear")
    src.add_argument("--files-from", help="Archivo con lista de rutas (una por línea)")
    src.add_argument("--from-result", help="Usar resultado JSON pre-calculado (no re-escanea)")
    parser.add_argument("--output", choices=["json", "telegram", "email", "comment"], default="json")
    args = parser.parse_args()

    if args.from_result:
        with open(args.from_result, encoding="utf-8") as f:
            result = json.load(f)
    else:
        files = []
        if args.files:
            files = args.files
        elif args.files_from:
            with open(args.files_from, encoding="utf-8") as f:
                files = [l.strip() for l in f if l.strip()]
        else:
            parser.error("Se requiere --files, --files-from, o --from-result")

        result = scan_files(files)
        if args.output == "json":
            print(json.dumps(result, indent=2, ensure_ascii=False))
            sys.exit(1 if result["is_vulnerable"] else 0)

    pr_info = _pr_info_from_env()

    if args.output == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.output == "comment":
        print(format_pr_comment(result))

    elif args.output == "telegram":
        msg = format_telegram(result, pr_info)
        print("[TELEGRAM]\n" + msg)
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        if token and chat_id:
            resp = send_telegram(msg, token, chat_id)
            if resp:
                print("[OK] Telegram enviado")
        else:
            print("[AVISO] TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID no configurados")

    elif args.output == "email":
        is_vuln = result["is_vulnerable"]
        status = "VULNERABLE" if is_vuln else "SEGURO"
        pr_num = pr_info.get("pr_number", "")
        repo = pr_info.get("repo", "")
        subject = f"[SECURITY] {'🔴' if is_vuln else '🟢'} {status} — PR #{pr_num} — {repo}"
        html = format_email_html(result, pr_info)

        smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = os.environ.get("SMTP_PORT", "587")
        email_from = os.environ.get("EMAIL_FROM", "")
        email_to = os.environ.get("EMAIL_TO", "")
        email_password = os.environ.get("EMAIL_PASSWORD", "")

        print(f"[EMAIL] {subject}")
        if email_from and email_to and email_password:
            send_email(subject, html, smtp_server, smtp_port, email_from, email_to, email_password)
        else:
            print("[AVISO] Credenciales de email no configuradas (EMAIL_FROM, EMAIL_TO, EMAIL_PASSWORD)")

    sys.exit(1 if result["is_vulnerable"] else 0)


if __name__ == "__main__":
    main()
