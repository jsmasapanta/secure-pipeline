import sqlite3

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    sql = "SELECT * FROM users WHERE user='" + username + "' AND pwd='" + password + "'"
    cursor.execute(sql)
    return cursor.fetchone()

def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    return cursor.fetchone()