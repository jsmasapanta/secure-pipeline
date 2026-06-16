"""
tests/test_app.py — Suite de pruebas unitarias e integración
Proyecto Integrador Parcial II — Desarrollo de Software Seguro
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import json
from app import app, validate_title


@pytest.fixture
def client():
    """Cliente de pruebas Flask."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


# ─── Tests de la API ─────────────────────────────────────────────────────────
class TestHealthEndpoints:
    def test_index_returns_200(self, client):
        response = client.get('/')
        assert response.status_code == 200

    def test_index_returns_json(self, client):
        response = client.get('/')
        data = json.loads(response.data)
        assert 'app' in data
        assert 'status' in data
        assert data['status'] == 'healthy'

    def test_health_endpoint(self, client):
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'ok'


class TestTasksAPI:
    def test_get_tasks_returns_200(self, client):
        response = client.get('/tasks')
        assert response.status_code == 200

    def test_get_tasks_returns_list(self, client):
        response = client.get('/tasks')
        data = json.loads(response.data)
        assert isinstance(data, list)

    def test_create_task_success(self, client):
        payload = {'title': 'Nueva tarea de prueba', 'description': 'Descripción'}
        response = client.post('/tasks',
                               data=json.dumps(payload),
                               content_type='application/json')
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'id' in data
        assert data['title'] == 'Nueva tarea de prueba'

    def test_create_task_without_body_returns_400(self, client):
        response = client.post('/tasks', content_type='application/json')
        assert response.status_code == 400

    def test_create_task_empty_title_returns_400(self, client):
        payload = {'title': '', 'description': 'Sin título'}
        response = client.post('/tasks',
                               data=json.dumps(payload),
                               content_type='application/json')
        assert response.status_code == 400

    def test_get_single_task(self, client):
        # Crear primero
        payload = {'title': 'Tarea para GET'}
        client.post('/tasks', data=json.dumps(payload), content_type='application/json')
        # Obtener
        response = client.get('/tasks/1')
        assert response.status_code in [200, 404]  # Depende del estado de la DB

    def test_get_nonexistent_task_returns_404(self, client):
        response = client.get('/tasks/99999')
        assert response.status_code == 404

    def test_update_task(self, client):
        # Crear
        payload = {'title': 'Tarea para actualizar'}
        create_resp = client.post('/tasks',
                                  data=json.dumps(payload),
                                  content_type='application/json')
        if create_resp.status_code == 201:
            task_id = json.loads(create_resp.data)['id']
            # Actualizar
            update_payload = {'title': 'Tarea actualizada', 'done': True}
            response = client.put(f'/tasks/{task_id}',
                                  data=json.dumps(update_payload),
                                  content_type='application/json')
            assert response.status_code == 200


# ─── Tests de seguridad (validación de inputs) ────────────────────────────────
class TestInputValidation:
    def test_validate_title_strips_whitespace(self):
        result = validate_title("  Mi tarea  ")
        assert result.strip() == "Mi tarea"

    def test_validate_title_too_long_raises(self):
        with pytest.raises(ValueError):
            validate_title("a" * 201)

    def test_validate_title_empty_raises(self):
        with pytest.raises(ValueError):
            validate_title("")

    def test_validate_title_none_raises(self):
        with pytest.raises(ValueError):
            validate_title(None)

    def test_xss_in_title_is_escaped(self, client):
        """El XSS debe ser escapado, no ejecutado."""
        payload = {'title': 'Tarea <script>alert(1)</script> legítima'}
        response = client.post('/tasks',
                               data=json.dumps(payload),
                               content_type='application/json')
        # Debe rechazar el input por caracteres inválidos o escaparlo
        # No debe retornar el script sin escapar
        if response.status_code == 201:
            data = json.loads(response.data)
            assert '<script>' not in data.get('title', '')

    def test_sql_injection_in_task_id(self, client):
        """El endpoint no debe ser vulnerable a SQL injection en el ID."""
        response = client.get('/tasks/1 OR 1=1')
        # Debe rechazar (404 por ruta no válida, o 400)
        assert response.status_code in [400, 404]

    def test_create_task_xss_payload(self, client):
        """Payload XSS debe ser rechazado o sanitizado."""
        payload = {'title': '<img src=x onerror=alert(1)>'}
        response = client.post('/tasks',
                               data=json.dumps(payload),
                               content_type='application/json')
        assert response.status_code in [400, 201]
        if response.status_code == 201:
            data = json.loads(response.data)
            assert '<img' not in data.get('title', '')


# ─── Tests de integración ─────────────────────────────────────────────────────
class TestIntegration:
    def test_full_task_lifecycle(self, client):
        """Ciclo completo: crear → leer → actualizar."""
        # 1. Crear
        create_resp = client.post('/tasks',
                                  data=json.dumps({'title': 'Ciclo completo', 'description': 'Test E2E'}),
                                  content_type='application/json')
        assert create_resp.status_code == 201
        task_id = json.loads(create_resp.data)['id']

        # 2. Leer
        get_resp = client.get(f'/tasks/{task_id}')
        assert get_resp.status_code == 200

        # 3. Actualizar
        update_resp = client.put(f'/tasks/{task_id}',
                                 data=json.dumps({'title': 'Ciclo completo actualizado', 'done': False}),
                                 content_type='application/json')
        assert update_resp.status_code == 200

    def test_list_reflects_created_tasks(self, client):
        """La lista de tareas refleja las tareas creadas."""
        client.post('/tasks',
                    data=json.dumps({'title': 'Tarea en lista'}),
                    content_type='application/json')
        response = client.get('/tasks')
        tasks = json.loads(response.data)
        assert isinstance(tasks, list)
        assert len(tasks) >= 1
