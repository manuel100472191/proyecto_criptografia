import sqlite3


class Db:
    def __init__(self):
        self.db_name = "base_de_datos.db"
        self.connection = sqlite3.connect(self.db_name)
        self.cursor = self.connection.cursor()

    def create_db(self):
        self.cursor.execute(""
                            "CREATE TABLE users ("
                            "telephone_number CHAR(9) PRIMARY KEY,"
                            "password VARCHAR2(255) NOT NULL,"
                            "name VARCHAR2(50) NOT NULL,"
                            "surname VARCHAR2(50) NOT NULL,"
                            "email VARCHAR2(100)"
                            ");")

        self.cursor.execute(""
                            "CREATE TABLE messages ("
                            "id INTEGER PRIMARY KEY,"
                            "sender CHAR(9) NOT NULL,"
                            "receiver CHAR(9) NOT NULL,"
                            "content VARCHAR2(512) NOT NULL,"
                            "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
                            "CONSTRAINT FK_SENDER FOREIGN KEY(sender) REFERENCES users,"
                            "CONSTRAINT FK_RECEIVER FOREIGN KEY(receiver) REFERENCES users"
                            ");")

    def reset_db(self):
        self.cursor.execute("DROP TABLE users;")
        self.cursor.execute("DROP TABLE messages;")

    def add_user(self, telephone, password, name, surname):
        self.cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?);", (telephone, password, name, surname))

    def validate_user(self, telephone, password):
        rows = list(self.cursor.execute("SELECT telephone_number, password FROM users WHERE telephone = ?;", (telephone,)))
        print(rows)
        if len(rows) != 1:
            return False
        if rows[0][1] == password:
            return True

    def populate_db(self):
        self.cursor.execute("INSERT INTO users VALUES ('delamola19', 'contraseña');")
        self.cursor.execute("INSERT INTO users VALUES ('user1', 'user1_pass');")
        self.connection.commit()

    def view_data(self):
        rows = self.cursor.execute("SELECT * from users").fetchall()
        for row in rows:
            print(f"user: {row[0]} ---- password: {row[1]}")
