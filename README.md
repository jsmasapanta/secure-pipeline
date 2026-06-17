# Secure CI/CD Pipeline con Detección de Vulnerabilidades por ML

**Universidad de las Fuerzas Armadas ESPE**  
Departamento de Ciencias de la Computación — Ingeniería en Software  
Desarrollo de Software Seguro — Proyecto Integrador Parcial II  
Profesor: Geovanny Cudco  
Estudiante: Jefferson Santiago Masapanta Guilcatoma  

---

## Descripción

Pipeline CI/CD completamente automatizado que integra un modelo de **Random Forest** (minería de datos tradicional) para detectar vulnerabilidades en código fuente antes de que llegue a producción.

> **IMPORTANTE:** No se usa ningún LLM (GPT, Claude, Llama, etc.). El modelo es un clasificador tradicional entrenado con scikit-learn.

---

## Flujo del Pipeline

```
Developer (rama dev)
        |
        | git push + Pull Request dev → test
        ↓
┌─────────────────────────────────────────┐
│  ETAPA 1: Análisis de Seguridad (ML)    │
│  • Extrae diff del PR                   │
│  • Extrae features del código           │
│  • Random Forest clasifica: SEGURO/VULN │
│  • Si VULNERABLE → bloquea + Telegram  │
│                   + Issue automática    │
└──────────────┬──────────────────────────┘
               │ Solo si SEGURO
               ↓
┌─────────────────────────────────────────┐
│  ETAPA 2: Pruebas Unitarias (pytest)    │
│  • 20 pruebas unitarias e integración   │
│  • Si fallan → bloquea + Telegram       │
└──────────────┬──────────────────────────┘
               │ Solo si pasan
               ↓
┌─────────────────────────────────────────┐
│  ETAPA 3: Deploy a Producción           │
│  • Deploy automático en Render          │
│  • Notificación Telegram con URL        │
└─────────────────────────────────────────┘
```

---

## Modelo de Machine Learning

### Algoritmo
**Random Forest Classifier** — scikit-learn (NO es un LLM)

### Dataset
Sintético basado en patrones del **Juliet Test Suite (NIST)** y **CVEFixes**:
- 240 muestras vulnerables
- 240 muestras seguras
- 480 muestras totales

### Vulnerabilidades cubiertas
| CWE | Descripción |
|-----|-------------|
| CWE-89 | SQL Injection |
| CWE-78 | OS Command Injection |
| CWE-79 | Cross-Site Scripting (XSS) |
| CWE-798 | Hardcoded Credentials |
| CWE-502 | Insecure Deserialization |
| CWE-22 | Path Traversal |
| CWE-95 | eval/exec Injection |

### Features extraídas (45 features)
| Feature | Descripción |
|---------|-------------|
| `ast_depth` | Profundidad máxima del AST |
| `dangerous_fn_count` | Funciones peligrosas (eval, exec, os.system...) |
| `sql_injection_patterns` | Concatenación en queries SQL |
| `cmd_injection_patterns` | Llamadas a shell con input del usuario |
| `xss_patterns` | Escritura directa en DOM |
| `hardcoded_secrets` | Credenciales hardcodeadas |
| `sanitization_count` | Funciones de sanitización presentes |
| `uses_parameterized` | Uso de consultas parametrizadas |
| `uses_orm` | Uso de ORM seguro |
| `is_safe_sql` | SQL seguro detectado |
| `uses_env_vars` | Secretos en variables de entorno |
| `has_try_except` | Manejo de errores presente |

### Resultados de Validación
```
Modelo:           Random Forest (100 estimadores)
Accuracy CV:      100% (5-fold cross-validation)
AUC-ROC:          1.0000
Dataset:          480 muestras balanceadas
Features:         45 features
```

---

## Setup del Pipeline

### 1. Clonar el repositorio

```bash
git clone https://github.com/jsmasapanta/secure-pipeline.git
cd secure-pipeline
```

### 2. Instalar dependencias

```bash
python -m venv venv
venv\Scripts\activate  # Windows
pip install scikit-learn xgboost pandas numpy joblib flask pytest pytest-cov
```

### 3. Entrenar el modelo

```bash
python model/train.py
# Genera: model/vulnerability_model.pkl
#         model/model_metadata.json
```

### 4. Probar el clasificador

```bash
# Código vulnerable
python model/classify.py --code "sql = 'SELECT * FROM users WHERE id=' + uid; cursor.execute(sql)" --output json

# Código seguro
python model/classify.py --code "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))" --output json
```

### 5. GitHub Secrets requeridos

| Secret | Descripción |
|--------|-------------|
| `TELEGRAM_BOT_TOKEN` | Token del bot de Telegram |
| `TELEGRAM_CHAT_ID` | ID del chat para notificaciones |
| `RENDER_DEPLOY_HOOK` | URL del deploy hook de Render |
| `RENDER_APP_URL` | URL de la app en producción |

### 6. Ramas requeridas

```bash
git checkout -b dev && git push origin dev
git checkout -b test && git push origin test
git checkout main && git push origin main
```

### 7. Branch Protection Rules

**Rama `test`:**
- Require status checks: `security-scan`

**Rama `main`:**
- Require status checks: `security-scan`, `run-tests`

---

## Bot de Telegram

**Bot:** @secure_pipeline_espe_bot

Notificaciones automáticas en cada fase:

| Evento | Mensaje |
|--------|---------|
| Inicio de análisis | Inicio de Analisis de Seguridad - PR #N |
| Resultado seguro | Resultado: SEGURO - Continuando pipeline |
| Resultado vulnerable | Resultado: VULNERABLE - Merge bloqueado |
| Pruebas iniciadas | Iniciando pruebas unitarias |
| Pruebas pasadas | Resultado pruebas: Todas las pruebas pasaron |
| Pruebas fallidas | Resultado pruebas: Pruebas fallidas |
| Deploy iniciado | Iniciando deploy a produccion |
| Deploy exitoso | Deploy exitoso en produccion - URL |

---

## App en Producción

**URL:** https://secure-pipeline.onrender.com

### Endpoints disponibles

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/` | Info de la app |
| GET | `/health` | Health check |
| GET | `/tasks` | Lista de tareas |
| POST | `/tasks` | Crear tarea |
| GET | `/tasks/:id` | Obtener tarea |
| PUT | `/tasks/:id` | Actualizar tarea |

---

## Estructura del Proyecto

```
secure-pipeline/
├── .github/
│   └── workflows/
│       └── secure-pipeline.yml    # Pipeline CI/CD completo
├── model/
│   ├── train.py                   # Entrenamiento del modelo
│   ├── classify.py                # Clasificador de vulnerabilidades
│   ├── vulnerability_model.pkl    # Modelo entrenado
│   └── model_metadata.json        # Metadatos del modelo
├── notebooks/
│   └── train_model.ipynb          # Notebook de entrenamiento
├── app/
│   ├── app.py                     # Aplicación Flask segura
│   ├── Dockerfile                 # Imagen Docker
│   ├── requirements.txt
│   └── tests/
│       └── test_app.py            # 20 pruebas unitarias
└── README.md
```

---

## Prueba del Pipeline

### Código VULNERABLE (bloqueado)
```python
# login_vulnerable.py
def login(username, password):
    sql = "SELECT * FROM users WHERE user='" + username + "' AND pwd='" + password + "'"
    cursor.execute(sql)  # SQL Injection detectado por el modelo
```

### Código SEGURO (pasa)
```python
# login_secure.py
def login(username, password):
    cursor.execute(
        "SELECT * FROM users WHERE user = %s AND pwd = %s",
        (username, hash_password(password))
    )
```

---

## Criterios de Evaluación

| Criterio | Estado |
|----------|--------|
| Pipeline completamente automatizado | Completado |
| Modelo ML propio sin LLM | Completado - Random Forest |
| Accuracy mayor a 82% en CV | Completado - 100% |
| Notificaciones Telegram en todas las fases | Completado |
| Issues automáticas al detectar vulnerabilidades | Completado |
| Despliegue automático funcional | Completado - Render |
| Branch protection rules activas | Completado |
| Notebook de entrenamiento incluido | Completado |

---

*Proyecto Integrador Parcial II — Desarrollo de Software Seguro*  
*Universidad de las Fuerzas Armadas ESPE — 2026*