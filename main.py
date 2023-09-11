import sqlite3
from base_de_datos import Db

base_de_datos = Db()

base_de_datos.create_db()
base_de_datos.populate_db()
base_de_datos.view_data()

# connection = sqlite3.connect("base_de_datos.db")
# print(connection.total_changes)
#
# cursor = connection.cursor()
# cursor.execute("DROP TABLE users;")
# cursor.execute(""
#                "CREATE TABLE users ("
#                "user_id VARCHAR2(100) PRIMARY KEY,"
#                "password VARCHAR2(255) NOT NULL"
#                ");")
#
# cursor.execute("INSERT INTO users VALUES ('delamola19', 'contraseña');")
# cursor.execute("INSERT INTO users VALUES ('user1', 'user1_pass');")
#
# user = "delamola19"
# rows = cursor.execute("SELECT * from users").fetchall()
# # rows = cursor.execute(f"SELECT * FROM users WHERE user_id = ?", (user,)).fetchall()
# print(rows)
