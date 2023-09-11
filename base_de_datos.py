import sqlite3


class Db:
    def __init__(self):
        self.db_name = "base_de_datos.db"
        self.connection = sqlite3.connect(self.db_name)
        self.cursor = self.connection.cursor()

    def create_db(self):
        self.cursor.execute("DROP TABLE users;")
        self.cursor.execute(""
                            "CREATE TABLE users ("
                            "user_id VARCHAR2(100) PRIMARY KEY,"
                            "password VARCHAR2(255) NOT NULL"
                            ");")

    def add_user(self, user_name, password):
        self.cursor.execute("INSERT INTO users VALUES (?, ?);", (user_name, password))

    def populate_db(self):
        self.cursor.execute("INSERT INTO users VALUES ('delamola19', 'contraseña');")
        self.cursor.execute("INSERT INTO users VALUES ('user1', 'user1_pass');")

    def view_data(self):
        rows = self.cursor.execute("SELECT * from users").fetchall()
        print(rows)
        for row in rows:
            print(f"user: {row[0]} ---- password: {row[1]}")
