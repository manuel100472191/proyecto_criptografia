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

    def add_user(self, telephone, password, name, surname, email):
        self.cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?);", (telephone, password, name, surname, email))
        self.connection.commit()

    def validate_user(self, telephone, password):
        rows = list(self.cursor.execute("SELECT telephone_number, password FROM users WHERE telephone_number = ?;"
                                        , (telephone,)))
        if len(rows) != 1:
            return False
        if rows[0][1] == password:
            return True
        return False

    def find_user(self, telephone):
        rows = list(self.cursor.execute("SELECT * FROM users WHERE telephone_number = ?;", (telephone,)))
        return rows[0]

    def find_messages_sent(self, telephone):
        rows = list(self.cursor.execute("SELECT * FROM messages WHERE sender = ?", (telephone,)))
        return rows

    def find_messages_received(self, telephone):
        rows = list(self.cursor.execute("SELECT * FROM messages WHERE receiver = ?", (telephone,)))
        return rows

    def add_message(self, sender, receiver, content):
        self.cursor.execute("INSERT INTO messages(sender, receiver, content) VALUES (?, ?, ?);"
                            , (sender, receiver, content))
        self.connection.commit()

    def populate_users(self):
        self.add_user('111111111', 'password', 'user1', 'user1', '1@hola.es')
        self.add_user('222222222', 'password', 'user2', 'user2', '2@hola.es')
        self.add_user('333333333', 'password', 'user3', 'user3', '3@hola.es')
        self.add_user('444444444', 'password', 'user4', 'user4', '4@hola.es')

    def populate_messages(self):
        self.add_message('111111111', '222222222', 'Hola')
        self.add_message('222222222', '333333333', '¿Que tal?')
        self.add_message('444444444', '111111111', 'Buenos dias')

    def view_data(self):
        rows = self.cursor.execute("SELECT * from users").fetchall()
        for row in rows:
            print(f"phone-number: {row[0]} ---- password: {row[1]} ----- name: {row[2]} ----- surname: {row[3]} ----"
                  f"email: {row[4]}")
        rows = self.cursor.execute("SELECT * FROM messages").fetchall()
        for row in rows:
            print(f"id: {row[0]} ---- sender: {row[1]} ---- receiver {row[2]} ---- content: {row[3]} "
                  f"---- timestamp: {row[4]}")
