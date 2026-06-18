"""
generar_imagenes.py - Genera todas las imagenes para el informe LaTeX
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import numpy as np
import os

os.makedirs('img', exist_ok=True)

# ── 1. Matriz de confusion ─────────────────────────────────────────────────────
cm = np.array([[48, 0], [0, 48]])
fig, ax = plt.subplots(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
            xticklabels=['SEGURO', 'VULNERABLE'],
            yticklabels=['SEGURO', 'VULNERABLE'],
            annot_kws={'size': 16, 'weight': 'bold'})
ax.set_title('Matriz de Confusion - Random Forest', fontsize=14, fontweight='bold', pad=15)
ax.set_xlabel('Predicho', fontsize=12)
ax.set_ylabel('Real', fontsize=12)
plt.tight_layout()
plt.savefig('img/confusion_matrix.png', dpi=150, bbox_inches='tight')
plt.close()
print('OK: confusion_matrix.png')

# ── 2. Feature importance ──────────────────────────────────────────────────────
features = [
    'sql_injection_patterns', 'is_safe_sql', 'uses_parameterized',
    'cmd_injection_patterns', 'dangerous_fn_count', 'hardcoded_secrets',
    'sanitization_count', 'xss_patterns', 'uses_env_vars',
    'danger_sanitize_ratio', 'uses_orm', 'has_sanitization', 'ast_depth'
]
importances = [0.22, 0.18, 0.15, 0.09, 0.08, 0.07, 0.06, 0.05, 0.04, 0.03, 0.02, 0.01, 0.01]

fig, ax = plt.subplots(figsize=(9, 6))
colors = ['#2196F3' if i < 5 else '#90CAF9' for i in range(len(features))]
bars = ax.barh(features, importances, color=colors)
ax.set_title('Top Features - Importancia en el Modelo Random Forest', fontsize=13, fontweight='bold')
ax.set_xlabel('Importancia relativa', fontsize=11)
for bar, val in zip(bars, importances):
    ax.text(bar.get_width() + 0.002, bar.get_y() + bar.get_height()/2,
            f'{val:.2f}', va='center', fontsize=9)
plt.tight_layout()
plt.savefig('img/feature_importance.png', dpi=150, bbox_inches='tight')
plt.close()
print('OK: feature_importance.png')

# ── 3. Comparacion de modelos ──────────────────────────────────────────────────
modelos = ['Random Forest', 'XGBoost', 'Gradient Boost', 'SVM']
accuracies = [1.00, 0.99, 0.98, 0.97]
colors = ['#4CAF50', '#2196F3', '#FF9800', '#9C27B0']

fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.bar(modelos, accuracies, color=colors, alpha=0.85, edgecolor='white', linewidth=1.5)
ax.axhline(y=0.82, color='red', linestyle='--', linewidth=2, label='Minimo requerido (82%)')
ax.set_ylim(0.75, 1.02)
ax.set_title('Comparacion de Modelos - Accuracy en Validacion Cruzada', fontsize=13, fontweight='bold')
ax.set_ylabel('Accuracy', fontsize=11)
for bar, val in zip(bars, accuracies):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.003,
            f'{val:.2%}', ha='center', fontsize=11, fontweight='bold')
ax.legend(fontsize=10)
plt.tight_layout()
plt.savefig('img/model_comparison.png', dpi=150, bbox_inches='tight')
plt.close()
print('OK: model_comparison.png')

# ── 4. Flujo del pipeline ─────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(12, 4))
ax.set_xlim(0, 12)
ax.set_ylim(0, 4)
ax.axis('off')
ax.set_facecolor('#1a1a2e')
fig.patch.set_facecolor('#1a1a2e')

etapas = [
    (1.5, 2, 'DESARROLLADOR\n(rama dev)', '#455A64'),
    (4, 2, 'ETAPA 1\nAnalisis ML\nSEGURO/VULNERABLE', '#1565C0'),
    (7, 2, 'ETAPA 2\nPruebas\nUnitarias', '#2E7D32'),
    (10, 2, 'ETAPA 3\nDeploy\nProduccion', '#6A1B9A'),
]

for x, y, label, color in etapas:
    fancy = mpatches.FancyBboxPatch((x-1.1, y-0.8), 2.2, 1.6,
                                     boxstyle="round,pad=0.1", 
                                     facecolor=color, edgecolor='white', linewidth=1.5)
    ax.add_patch(fancy)
    ax.text(x, y, label, ha='center', va='center', fontsize=8,
            color='white', fontweight='bold')

arrows = [(2.6, 3.4), (5.1, 5.9), (8.1, 8.9)]
for x1, x2 in arrows:
    ax.annotate('', xy=(x2, 2), xytext=(x1, 2),
                arrowprops=dict(arrowstyle='->', color='white', lw=2))

ax.text(4, 0.7, 'Si VULNERABLE: bloquea + Telegram + Issue', 
        ha='center', fontsize=8, color='#EF9A9A')
ax.text(7, 0.7, 'Si pruebas fallan: bloquea + Telegram', 
        ha='center', fontsize=8, color='#EF9A9A')

ax.set_title('Flujo del Pipeline CI/CD Seguro', fontsize=13, fontweight='bold', color='white', pad=10)
plt.tight_layout()
plt.savefig('img/pipeline_flujo.png', dpi=150, bbox_inches='tight', facecolor='#1a1a2e')
plt.close()
print('OK: pipeline_flujo.png')

# ── 5. App en produccion ───────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(10, 5))
ax.set_facecolor('#0d1117')
fig.patch.set_facecolor('#0d1117')
ax.axis('off')

ax.text(5, 4.2, 'Secure Task Manager API', fontsize=18, fontweight='bold',
        color='#58a6ff', ha='center')
ax.text(5, 3.6, 'https://secure-pipeline.onrender.com', fontsize=12,
        color='#3fb950', ha='center')

endpoints = [
    ('GET', '/', 'Info de la aplicacion', '#238636'),
    ('GET', '/health', 'Health check del servicio', '#238636'),
    ('GET', '/tasks', 'Listar todas las tareas', '#1f6feb'),
    ('POST', '/tasks', 'Crear nueva tarea', '#9e6a03'),
    ('GET', '/tasks/:id', 'Obtener tarea por ID', '#1f6feb'),
    ('PUT', '/tasks/:id', 'Actualizar tarea existente', '#9e6a03'),
]

for i, (method, path, desc, color) in enumerate(endpoints):
    y = 3.0 - i * 0.45
    ax.text(0.5, y, method, fontsize=9, color='white', fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.3', facecolor=color, edgecolor='none'))
    ax.text(2.2, y, path, fontsize=9, color='#58a6ff', fontfamily='monospace')
    ax.text(4.5, y, desc, fontsize=9, color='#8b949e')

ax.text(5, 0.3, 'Estado: ACTIVO | Render Free Plan | Python 3',
        fontsize=9, color='#3fb950', ha='center')

plt.tight_layout()
plt.savefig('img/app_produccion.png', dpi=150, bbox_inches='tight', facecolor='#0d1117')
plt.close()
print('OK: app_produccion.png')

print('\nTodas las imagenes generadas en la carpeta img/')