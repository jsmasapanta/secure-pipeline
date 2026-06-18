import os
import sqlite3

# Vulnerabilidad 1: OS Command Injection
def ejecutar_comando(user_input):
    os.system("ls " + user_input)

# Vulnerabilidad 2: SQL Injection (concatenación insegura)
def consulta_insegura(user_id):
    conn = sqlite3.connect("db.sqlite")
    query = "SELECT * FROM users WHERE id = " + user_id
    conn.execute(query) 
