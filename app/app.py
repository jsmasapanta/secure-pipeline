"""
app.py — Aplicación Flask de ejemplo para el proyecto
Una API REST segura de gestión de tareas
"""
from flask import Flask, jsonify, request
import os
import re
import html
import sqlite3
import hashlib
import secrets
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── Base de datos ──────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute('''CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        done INTEGER DEFAULT 0
    )''')
    conn.execute("INSERT INTO tasks (title, description) VALUES (?, ?)",
                 ("Tarea de ejemplo", "Esta es una tarea de prueba"))
    conn.commit()
    return conn


def validate_title(title: str) -> str:
    """Valida y sanitiza el título de una tarea."""
    if not title or not isinstance(title, str):
        raise ValueError("El título es requerido")
    title = title.strip()
    if len(title) > 200:
        raise ValueError("El título no puede exceder 200 caracteres")
    if not re.match(r'^[\w\s\-\.,:;!?()áéíóúÁÉÍÓÚñÑüÜ]+$', title):
        raise ValueError("El título contiene caracteres no permitidos")
    return html.escape(title)


# ─── Rutas ──────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return jsonify({
        'app': 'Secure Task Manager',
        'version': '1.0.0',
        'status': 'healthy',
        'environment': os.environ.get('ENVIRONMENT', 'development')
    })


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'secure-task-api'})


@app.route('/tasks', methods=['GET'])
def get_tasks():
    try:
        db = get_db()
        # ✅ Consulta parametrizada — sin SQL injection
        tasks = db.execute("SELECT * FROM tasks WHERE done = ?", (0,)).fetchall()
        return jsonify([dict(t) for t in tasks])
    except Exception as e:
        logger.error(f"Error al obtener tareas: {e}")
        return jsonify({'error': 'Error interno'}), 500


@app.route('/tasks/<int:task_id>', methods=['GET'])
def get_task(task_id):
    try:
        db = get_db()
        # ✅ Consulta parametrizada
        task = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not task:
            return jsonify({'error': 'Tarea no encontrada'}), 404
        return jsonify(dict(task))
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({'error': 'Error interno'}), 500


@app.route('/tasks', methods=['POST'])
def create_task():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON requerido'}), 400

        # ✅ Validación y sanitización
        title = validate_title(data.get('title', ''))
        description = html.escape(str(data.get('description', '')))[:1000]

        db = get_db()
        # ✅ Parámetros preparados
        cursor = db.execute(
            "INSERT INTO tasks (title, description) VALUES (?, ?)",
            (title, description)
        )
        db.commit()

        return jsonify({'id': cursor.lastrowid, 'title': title, 'description': description}), 201

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error al crear tarea: {e}")
        return jsonify({'error': 'Error interno'}), 500


@app.route('/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON requerido'}), 400

        db = get_db()
        task = db.execute("SELECT id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not task:
            return jsonify({'error': 'Tarea no encontrada'}), 404

        title = validate_title(data.get('title', ''))
        done = int(bool(data.get('done', False)))

        # ✅ UPDATE parametrizado
        db.execute("UPDATE tasks SET title = ?, done = ? WHERE id = ?",
                   (title, done, task_id))
        db.commit()

        return jsonify({'id': task_id, 'title': title, 'done': bool(done)})

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({'error': 'Error interno'}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('ENVIRONMENT') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)
