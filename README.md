# 🔐 Secure CI/CD Pipeline con Detección de Vulnerabilidades por ML

**Universidad de las Fuerzas Armadas ESPE**  
Desarrollo de Software Seguro — Proyecto Integrador Parcial II 
Integrantes: Wilmer Buestan y Jefferson Masapanta
Profesor: Geovanny Cudco

---

## 📋 Descripción

Pipeline CI/CD completamente automatizado que integra un modelo de **Random Forest** (minería de datos) para detectar vulnerabilidades en código fuente antes de que llegue a producción.

```
dev branch → PR → [ML Security Scan] → [Unit Tests] → merge main → [Deploy Render]
                         ↓                    ↓
                  Telegram notify       Telegram notify
```

## 🏗️ Arquitectura del Pipeline

```
┌─────────────────────────────────────────────────────────┐
│                   DEVELOPER (rama dev)                  │
│                         git push                        │
│                    Pull Request → test                  │
└──────────────────────────┬──────────────────────────────┘
                           │ Trigger automático
                           ▼
┌─────────────────────────────────────────────────────────┐
│  ETAPA 1: Análisis de Seguridad (Random Forest)         │
│  • Extrae diff del PR                                   │
│  • Extrae features: AST, tokens, funciones peligrosas   │
│  • Clasifica: SEGURO / VULNERABLE                       │
│  • Si VULNERABLE → bloquea + Telegram + Issue           │
└──────────────────────────┬──────────────────────────────┘
                           │ Solo si SEGURO
                           ▼
┌─────────────────────────────────────────────────────────┐
│  ETAPA 2: Pruebas Unitarias & Integración               │
│  • pytest con cobertura de código                       │
│  • Si fallan → bloquea + Telegram + label               │
└──────────────────────────┬──────────────────────────────┘
                           │ Solo si pasan
                           ▼
┌─────────────────────────────────────────────────────────┐
│  ETAPA 3: Deploy a Producción                           │
│  • Build imagen Docker                                  │
│  • Deploy en Render via webhook                         │
│  • Notificación Telegram de éxito                       │
└─────────────────────────────────────────────────────────┘
```

## 🤖 Modelo de Machine Learning

### Algoritmo
**Random Forest Classifier** (scikit-learn) — clasificador tradicional de minería de datos.  
> ⚠️ **NO se usa ningún LLM** (GPT, Claude, Llama, etc.)

### Dataset
Sintético basado en patrones del **Juliet Test Suite (NIST)** y **CVEFixes**, cubriendo:
- CWE-89: SQL Injection
- CWE-78: OS Command Injection  
- CWE-79: Cross-Site Scripting (XSS)
- CWE-798: Hardcoded Credentials
- CWE-502: Insecure Deserialization
- CWE-22: Path Traversal
- CWE-95: eval/exec injection

### Features extraídas
| Feature | Descripción |
|---------|-------------|
| `ast_depth` | Profundidad máxima del AST |
| `dangerous_fn_count` | # de funciones peligrosas (eval, exec, os.system...) |
| `sql_injection_patterns` | Patrones de concatenación en queries SQL |
| `cmd_injection_patterns` | Llamadas a shell con input no sanitizado |
| `xss_patterns` | Escritura directa en DOM sin escape |
| `hardcoded_secrets` | Credenciales hardcodeadas en código |
| `sanitization_count` | # de funciones de sanitización presentes |
| `has_try_except` | Manejo de errores presente |
| `uses_env_vars` | Uso de variables de entorno para secretos |
| `danger_sanitize_ratio` | Ratio peligro/sanitización |
| + 30 más... | Tokens, longitud, patrones de sanitización específicos |

### Resultados de Validación
```
Modelo: Random Forest (200 estimadores)
Accuracy CV (5-fold): ≥ 82%
AUC-ROC: ≥ 0.90
Dataset: ~800 muestras balanceadas
```

Ver el notebook completo: [`notebooks/train_model.ipynb`](notebooks/train_model.ipynb)

## 🚀 Setup del Pipeline

### 1. Clonar y preparar el repositorio

```bash
git clone https://github.com/TU_USUARIO/secure-pipeline.git
cd secure-pipeline

# Crear ramas requeridas
git checkout -b dev && git push origin dev
git checkout -b test && git push origin test
git checkout main && git push origin main
```

### 2. Configurar GitHub Secrets

En `Settings → Secrets and variables → Actions`, agregar:

| Secret | Descripción |
|--------|-------------|
| `TELEGRAM_BOT_TOKEN` | Token del bot de Telegram (BotFather) |
| `TELEGRAM_CHAT_ID` | ID del chat/grupo para notificaciones |
| `RENDER_DEPLOY_HOOK` | URL del deploy hook de Render |
| `RENDER_APP_URL` | URL de tu app en Render |

### 3. Entrenar el modelo

```bash
pip install scikit-learn xgboost pandas numpy matplotlib joblib
jupyter notebook notebooks/train_model.ipynb
# Ejecutar todas las celdas → genera model/vulnerability_model.pkl
git add model/vulnerability_model.pkl model/model_metadata.json
git commit -m "feat: add trained vulnerability detection model"
git push
```

### 4. Configurar Branch Protection Rules

En GitHub → `Settings → Branches`:

**Para rama `test`:**
- ✅ Require status checks to pass: `security-scan`
- ✅ Require branches to be up to date

**Para rama `main`:**
- ✅ Require status checks to pass: `security-scan`, `run-tests`
- ✅ Require branches to be up to date
- ✅ Restrict pushes (solo via PR)

### 5. Configurar bot de Telegram

```bash
# 1. Hablar con @BotFather en Telegram
# 2. /newbot → darle un nombre → obtener token
# 3. Agregar el bot al grupo/chat
# 4. Obtener el chat_id:
curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
```

## 🧪 Probar el Pipeline

### Código VULNERABLE (debe ser rechazado)
```python
# vulnerable_code.py
def login(username, password):
    query = "SELECT * FROM users WHERE user='" + username + "' AND pwd='" + password + "'"
    cursor.execute(query)  # SQL Injection!
    return cursor.fetchone()

def run_command(cmd):
    os.system(cmd)  # Command Injection!
```

### Código SEGURO (debe pasar)
```python
# secure_code.py
def login(username, password):
    cursor.execute(
        "SELECT * FROM users WHERE user = %s AND pwd = %s",
        (username, hash_password(password))  # Parametrizado ✅
    )
    return cursor.fetchone()
```

### Flujo de prueba
```bash
git checkout dev
# Agregar código vulnerable
echo "cursor.execute('SELECT * FROM users WHERE id=' + user_id)" > test_vuln.py
git add test_vuln.py && git commit -m "test: add vulnerable code"
git push origin dev
# Abrir PR: dev → test en GitHub
# → El pipeline detectará la vulnerabilidad y bloqueará el merge
```

## 📱 Bot de Telegram

El bot envía notificaciones en los siguientes eventos:

| Evento | Mensaje |
|--------|---------|
| Inicio de análisis | 🔍 Análisis iniciado + datos del PR |
| Resultado seguro | 🟢 SEGURO + probabilidad + confianza |
| Resultado vulnerable | 🔴 VULNERABLE + tipos de vulnerabilidad |
| Pruebas pasadas | ✅ Todas las pruebas aprobadas |
| Pruebas fallidas | ❌ Tests fallidos + bloqueo |
| Deploy exitoso | 🎉 URL de producción |
| Deploy fallido | ❌ Error en producción |

**Capturas del bot:** *(agregar screenshots aquí)*

## 🌐 Despliegue en Producción

App desplegada en **Render**: [https://tu-app.onrender.com](https://tu-app.onrender.com)

```bash
# Endpoints disponibles:
GET  /           → Info de la app
GET  /health     → Health check
GET  /tasks      → Lista de tareas
POST /tasks      → Crear tarea
GET  /tasks/:id  → Obtener tarea
PUT  /tasks/:id  → Actualizar tarea
```

## 📁 Estructura del Proyecto

```
secure-pipeline/
├── .github/
│   └── workflows/
│       └── secure-pipeline.yml    # Pipeline completo CI/CD
├── model/
│   ├── classify.py                # Script de clasificación ML
│   ├── vulnerability_model.pkl    # Modelo entrenado (generado)
│   └── model_metadata.json        # Metadatos del modelo (generado)
├── notebooks/
│   └── train_model.ipynb          # Notebook de entrenamiento
├── app/
│   ├── app.py                     # Aplicación Flask
│   ├── Dockerfile                 # Imagen Docker
│   ├── requirements.txt
│   └── tests/
│       └── test_app.py            # Suite de pruebas pytest
└── README.md
```

## 📊 Criterios de Evaluación

| Criterio | Estado |
|----------|--------|
| Pipeline completamente automatizado | ✅ |
| Modelo ML propio (sin LLM) | ✅ Random Forest |
| Accuracy ≥ 82% en CV | ✅ |
| Notificaciones Telegram en todas las fases | ✅ |
| Issues automáticas al detectar vulnerabilidades | ✅ |
| Despliegue automático funcional | ✅ Render |
| Branch protection rules activas | ✅ |
| Notebook de entrenamiento incluido | ✅ |

---

*Proyecto Integrador Parcial II — Desarrollo de Software Seguro*  
*Universidad de las Fuerzas Armadas ESPE — 2026*
