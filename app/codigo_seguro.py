
def login_seguro(username, password):
    cursor.execute("SELECT * FROM users WHERE user = %s AND pwd = %s", (username, password))
    return cursor.fetchone()

