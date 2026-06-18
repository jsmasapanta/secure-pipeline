# Pipeline CI/CD Seguro con Detección de Vulnerabilidades por IA

**Universidad de las Fuerzas Armadas ESPE**
Departamento de Ciencias de la Computación — Ingeniería en Software
Desarrollo de Software Seguro — Proyecto Integrador Parcial II
Profesor: Geovanny Cudco | 2026

---

## Descripción

Pipeline CI/CD completamente automatizado que integra un modelo de **Random Forest** (minería de datos) para detectar vulnerabilidades en código fuente. El código vulnerable es rechazado automáticamente; solo el código seguro llega a producción.

> **IMPORTANTE:** Este sistema NO usa LLM (GPT, Claude, Llama, etc.). El modelo es un clasificador Random Forest entrenado con scikit-learn sobre dataset público (Juliet Test Suite NIST + CVEFixes).

---

## Flujo del Pipeline

```
DEV BRANCH
    │  (git push)
    ▼
Pull Request dev → test   ← trigger automático
    │
    ▼
ETAPA 1: Análisis de Seguridad (Random Forest + Bandit)
  • Descarga el diff del PR
  • Extrae 45 features: AST depth, tokens, funciones peligrosas, sanitización
  • Clasifica: SEGURO / VULNERABLE
  │
  ├─ Si VULNERABLE:
  │    → Bloquea el merge (exit 1)
  │    → Comentario en PR (CWE, línea, código)
  │    → Label "fixing-required" + Issue automática
  │    → Telegram + Email detallado
  │
  └─ Si SEGURO → continúa
    │
    ▼
ETAPA 2: Pruebas Unitarias (pytest)
  • Si fallan → bloquea + label "tests-failed" + Telegram + Email
    │
    ▼
ETAPA 3: Deploy a Producción (Render webhook)
  • Notificación Telegram + Email de deploy
    │
    ▼
MERGE AUTOMÁTICO
  • Merge PR dev → test  (automático vía API)
  • Merge test → main    (automático vía API)
  • Notificación final: pipeline completado (Telegram + Email)
```

---

## Notificaciones Implementadas

| Evento | Telegram | Email HTML |
|--------|----------|------------|
| Inicio de análisis de seguridad | ✅ | — |
| Resultado SEGURO | ✅ | ✅ |
| Resultado VULNERABLE (con CWE, línea, snippet) | ✅ | ✅ |
| Inicio pruebas unitarias | ✅ | — |
| Pruebas pasadas | ✅ | ✅ |
| Pruebas fallidas | ✅ | ✅ |
| Iniciando deploy | ✅ | — |
| Deploy exitoso | ✅ | ✅ |
| Merge a test completado | ✅ | — |
| Pipeline completo (merge a main) | ✅ | ✅ |

---

## Modelo de Machine Learning

### Algoritmo: Random Forest Classifier (scikit-learn) — NO es LLM

```python
# model/train.py — entrenado localmente
from sklearn.ensemble import RandomForestClassifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
```

### Dataset

Sintético basado en **Juliet Test Suite (NIST)** y **CVEFixes** — 480 muestras balanceadas.

| CWE | Vulnerabilidad |
|-----|----------------|
| CWE-89 | SQL Injection |
| CWE-78 | OS Command Injection |
| CWE-79 | Cross-Site Scripting (XSS) |
| CWE-798 | Hardcoded Credentials |
| CWE-502 | Insecure Deserialization |
| CWE-22 | Path Traversal |
| CWE-95 | eval/exec Injection |

### Features Extraídas (45 features)

| Categoría | Features |
|-----------|----------|
| Métricas de código | `num_lines`, `num_tokens`, `avg_line_length`, `ast_depth` |
| Funciones peligrosas | `uses_eval`, `uses_exec`, `uses_os_system`, `dangerous_fn_count` |
| Patrones de ataque | `sql_injection_patterns`, `cmd_injection_patterns`, `xss_patterns` |
| Sanitización | `sanitization_count`, `has_sanitization`, `uses_parameterized` |
| Buenas prácticas | `uses_env_vars`, `has_try_except`, `danger_sanitize_ratio` |

### Resultados de Validación

```
Modelo:           Random Forest Classifier (100 estimadores)
Dataset:          480 muestras — Juliet Test Suite (NIST) + CVEFixes
CV Accuracy:      100% (5-fold cross-validation)  ← supera el 82% requerido
AUC-ROC:          1.00
Archivo modelo:   model/vulnerability_model.pkl
Metadatos:        model/model_metadata.json
```

Ver el notebook completo: [`notebooks/entrenamiento_modelo.ipynb`](notebooks/entrenamiento_modelo.ipynb)

---

## Setup del Pipeline

### 1. Clonar el repositorio

```bash
git clone https://github.com/jsmasapanta/secure-pipeline.git
cd secure-pipeline
```

### 2. Configurar GitHub Secrets

En `Settings → Secrets and variables → Actions → New repository secret`:

| Secret | Descripción | Requerido |
|--------|-------------|-----------|
| `TELEGRAM_BOT_TOKEN` | Token del bot (BotFather → /newbot) | ✅ |
| `TELEGRAM_CHAT_ID` | ID del chat/grupo de Telegram | ✅ |
| `EMAIL_FROM` | Correo origen (Gmail recomendado) | ✅ |
| `EMAIL_TO` | Correo destino de notificaciones | ✅ |
| `EMAIL_PASSWORD` | Contraseña de aplicación Gmail | ✅ |
| `RENDER_DEPLOY_HOOK` | URL del deploy hook de Render | ✅ |
| `RENDER_APP_URL` | URL pública de la app en Render | ✅ |
| `SMTP_SERVER` | Servidor SMTP (default: smtp.gmail.com) | opcional |
| `SMTP_PORT` | Puerto SMTP (default: 587) | opcional |

**Nota:** Para `EMAIL_PASSWORD` usar una [contraseña de aplicación Google](https://myaccount.google.com/apppasswords).

### 3. Configurar Branch Protection Rules

En GitHub → `Settings → Branches → Add branch ruleset`:

**Rama `test`:**
- Require status checks: `Etapa 1 — Análisis de Seguridad (ML + Bandit)`
- Require branches to be up to date: ✅

**Rama `main`:**
- Require status checks: `Etapa 1 — Análisis de Seguridad (ML + Bandit)` + `Etapa 2 — Pruebas Unitarias`
- Require branches to be up to date: ✅
- Restrict direct pushes: ✅

### 4. Configurar Bot de Telegram

```bash
# 1. Telegram → buscar @BotFather → /newbot → obtener TOKEN
# 2. Agregar el bot al grupo/chat destino
# 3. Obtener CHAT_ID:
curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
# chat_id aparece en result[0].message.chat.id
```

### 5. Configurar Deploy en Render

```
1. render.com → New Web Service → Connect GitHub → secure-pipeline
2. Root Directory: app
3. Build Command: pip install -r requirements.txt
4. Start Command: gunicorn --bind 0.0.0.0:$PORT --workers 2 app:app
5. Environment: ENVIRONMENT=production
6. Settings → Deploy Hooks → Create hook → copiar URL
7. Guardar en GitHub Secrets como RENDER_DEPLOY_HOOK
```

---

## Probar el Pipeline

### Código VULNERABLE → debe ser rechazado

```python
# archivo_vulnerable.py
def login(username, password, db):
    query = "SELECT * FROM users WHERE user='" + username + "'"  # CWE-89
    db.execute(query)

def run_cmd(cmd):
    import os
    os.system(cmd)  # CWE-78

SECRET_KEY = "clave_secreta_123"  # CWE-798
```

```bash
git checkout dev
# Agregar el archivo vulnerable y hacer push
git add archivo_vulnerable.py
git commit -m "test: código vulnerable"
git push origin dev
# Crear PR dev → test en GitHub
# El pipeline detecta las vulnerabilidades y bloquea el merge
```

### Código SEGURO → pasa todos los checks

```python
# task_service.py
def get_task(task_id):
    db = _get_db()
    row = db.execute(
        "SELECT * FROM tasks WHERE id = ?",  # Parametrizado ✅
        (task_id,)
    ).fetchone()
    return Task.from_row(row)
```

---

## Estructura del Proyecto

```
secure-pipeline/
├── .github/
│   ├── workflows/
│   │   └── secure-pipeline.yml    # Pipeline CI/CD (4 jobs)
│   ├── CODEOWNERS                 # Protección de ramas críticas
│   ├── ISSUE_TEMPLATE/
│   │   ├── user_story.md          # Template Scrum + criterios CWE
│   │   └── security_bug.md        # Template de vulnerabilidades
│   └── pull_request_template.md   # Checklist DoD con seguridad
│
├── model/
│   ├── train.py                   # Script de entrenamiento
│   ├── classify.py                # Clasificador ML (features + predicción)
│   ├── scanner.py                 # Scanner multi-archivo (Bandit + ML)
│   ├── vulnerability_model.pkl    # Modelo entrenado (Random Forest)
│   └── model_metadata.json        # accuracy=1.0, AUC-ROC=1.0
│
├── notebooks/
│   └── entrenamiento_modelo.ipynb # Notebook de entrenamiento del modelo
│
├── app/
│   ├── app.py                     # Flask factory (create_app)
│   ├── config.py                  # Dev / Test / Production configs
│   ├── Dockerfile                 # imagen Docker (gunicorn, non-root)
│   ├── requirements.txt
│   ├── routes/                    # Capa de rutas (Blueprints)
│   ├── services/                  # Capa de lógica de negocio
│   ├── models/                    # Capa de modelos (dataclasses)
│   ├── security/                  # Validación, sanitización, cabeceras
│   └── tests/
│       └── test_app.py            # 23 tests (API + seguridad + integración)
│
└── test_fixtures/
    └── vulnerable/                # Fixtures educativos (excluidos del scan)
```

---

## Arquitectura Backend (Separación por Capas)

```
Request HTTP
    │
    ▼
routes/         ← Blueprints Flask, validación HTTP, serialización
    │
    ▼
security/       ← Validación inputs (OWASP ASVS 5.1), html.escape, regex
    │
    ▼
services/       ← Lógica de negocio, queries SQL parametrizadas
    │
    ▼
models/         ← Dataclasses (Task), representación de datos
    │
    ▼
security/headers.py  ← after_request: CSP, X-Frame-Options, nosniff
```

---

## Criterios de Evaluación

| Criterio | Estado | Evidencia |
|----------|--------|-----------|
| Pipeline completamente automatizado | ✅ | 4 jobs: scan→tests→deploy→merge |
| Modelo ML propio sin LLM | ✅ | Random Forest en `model/vulnerability_model.pkl` |
| Accuracy ≥ 82% en CV | ✅ | 100% (5-fold) en `model/model_metadata.json` |
| Notificaciones Telegram todas las fases | ✅ | 8 eventos, ver workflow |
| Notificaciones Email todas las fases | ✅ | HTML en 5 eventos, ver workflow |
| Issues automáticas al detectar vulns | ✅ | Con CWE, línea, fragmento de código |
| Merge automático dev→test | ✅ | Job `auto-merge` |
| Merge automático test→main | ✅ | `repos.merge` + fallback PR |
| Label "fixing-required" | ✅ | Job `security-scan` |
| Label "tests-failed" | ✅ | Job `run-tests` |
| Deploy automático en Render | ✅ | Webhook + notificación |
| Branch protection rules | ✅ | Ver sección Setup |
| Notebook de entrenamiento | ✅ | `notebooks/entrenamiento_modelo.ipynb` |
| Informe técnico | pendiente | (entrega separada en LaTeX) |

---

## Despliegue en Producción

App desplegada en **Render** — URL configurada en `RENDER_APP_URL` GitHub Secret.

```
GET  /           → Info de la app + arquitectura
GET  /health     → Health check
GET  /tasks      → Lista tareas
POST /tasks      → Crear tarea { "title": "...", "description": "..." }
GET  /tasks/:id  → Obtener tarea
PUT  /tasks/:id  → Actualizar { "title": "...", "done": true }
```

---

*Proyecto Integrador Parcial II — Desarrollo de Software Seguro*


*Universidad de las Fuerzas Armadas ESPE — Junio 2026*


*Profesor: Geovanny Cudco*
