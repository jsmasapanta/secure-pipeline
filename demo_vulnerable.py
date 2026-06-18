import sqlite3
import os
import subprocess

# CWE-89: SQL Injection
def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE user='" + username + "' AND pwd='" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()

# CWE-78: Command Injection
def ping(host):
    os.system("ping -c 1 " + host)

# CWE-798: Hardcoded credentials
API_KEY = "sk-abc123secretkey9999"
DB_PASSWORD = "admin123"
