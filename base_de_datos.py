import sqlite3
from cryptobro import Crypto_bro


class Db:
    def __init__(self):
        """ Creates the connection with the database and with the crypto functions"""
        self.db_name = "base_de_datos.db"
        self.connection = sqlite3.connect(self.db_name)
        self.cursor = self.connection.cursor()
        self.cursor.execute("PRAGMA foreign_keys = 1")
        self.crypto = Crypto_bro()

    def reset_db(self):
        """ Resets the database to a initial state with some users and messages"""
        self.delete_db()
        self.create_db()
        self.populate_users()
        self.populate_messages()

    def create_db(self):
        """ Creates the tables of the database """
        self.cursor.execute(""
                            "CREATE TABLE users ("
                            "telephone_number CHAR(9) PRIMARY KEY,"
                            "password_token CHAR(349) NOT NULL,"
                            "name VARCHAR2(100) NOT NULL,"
                            "surname VARCHAR2(100) NOT NULL,"
                            "email VARCHAR2(100),"
                            "password_salt CHAR(25),"
                            "key_salt CHAR(25),"
                            "name_nonce CHAR(17),"
                            "surname_nonce CHAR(17),"
                            "email_nonce CHAR(17)"
                            ");")

        self.cursor.execute(""
                            "CREATE TABLE messages ("
                            "id INTEGER PRIMARY KEY,"
                            "sender CHAR(9) NOT NULL,"
                            "receiver CHAR(9) NOT NULL,"
                            "content VARCHAR2(512) NOT NULL,"
                            "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
                            "FOREIGN KEY(sender) REFERENCES users(telephone_number),"
                            "FOREIGN KEY(receiver) REFERENCES users(telephone_number)"
                            ");")

    def delete_db(self):
        """ Deletes the tables from teh database """
        self.cursor.execute("DROP TABLE messages;")
        self.cursor.execute("DROP TABLE users;")

    def add_user(self, telephone, password, name, surname, email):
        """ Adds a user to the database given the correct data"""
        # Generates the salt and the password token for the user
        password_salt, password_token = self.crypto.create_password(password)
        # Generates the key_salt and the key for the user to encrypt its data
        key_salt, key = self.crypto.first_derive_key_from_password(password)
        # Encrypts the data and generates an once for each field
        name_nonce, name = self.crypto.encrypt_my_data(key, name)
        surname_nonce, surname = self.crypto.encrypt_my_data(key, surname)
        email_nonce, email = self.crypto.encrypt_my_data(key, email)
        # Stores the data into the database
        self.cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                            (telephone, password_token, name, surname, email,
                             password_salt, key_salt, name_nonce, surname_nonce, email_nonce))
        self.connection.commit()
        return key

    def validate_user(self, telephone, password):
        # Validates the log-in information of a user
        rows = list(self.cursor.execute("SELECT telephone_number, password_token, password_salt, key_salt "
                                        "FROM users WHERE telephone_number = ?;"
                                        , (telephone,)))
        # Verify that the password is the correct one and generates the key for the decryption
        if self.crypto.verify_password(password, rows[0][2], rows[0][1]):
            return self.crypto.derive_key_from_password(rows[0][3], password)
        return False

    def find_user(self, telephone):
        """ Returns all the information from an user given its phone_number"""
        rows = list(self.cursor.execute("SELECT * FROM users WHERE telephone_number = ?;", (telephone,)))
        return rows[0]

    def find_messages_sent(self, telephone):
        """ Find the messages that a phone a number has sent"""
        rows = list(self.cursor.execute("SELECT * FROM messages WHERE sender = ?", (telephone,)))
        return rows

    def find_messages_received(self, telephone):
        """ Finds the messages that a phone number has received """
        rows = list(self.cursor.execute("SELECT * FROM messages WHERE receiver = ?", (telephone,)))
        return rows

    def add_message(self, sender, receiver, content):
        """ Adds a message to the database """
        self.cursor.execute("INSERT INTO messages(sender, receiver, content) VALUES (?, ?, ?);"
                            , (sender, receiver, content))
        self.connection.commit()

    def populate_users(self):
        self.add_user('111111111', 'password', 'user1', 'user1', '1@hola.es')
        self.add_user('222222222', 'password', 'user2', 'user2', '2@hola.es')
        self.add_user('333333333', 'password', 'user3', 'user3', '3@hola.es')
        self.add_user('444444444', 'password', 'user4', 'user4', '4@hola.es')
        self.add_user('555555555', 'password', 'user5', 'user5', '5@hola.es')
        self.add_user('666666666', 'password', 'user6', 'user6', '6@hola.es')
        self.add_user('777777777', 'password', 'user7', 'user7', '7@hola.es')
        self.add_user('888888888', 'password', 'user8', 'user8', '8@hola.es')
        self.add_user('999999999', 'password', 'user9', 'user9', '9@hola.es')


    def populate_messages(self):
        self.add_message('111111111', '222222222', 'Hola')
        self.add_message('222222222', '333333333', '¿Que tal?')
        self.add_message('444444444', '111111111', 'Buenos dias')

    def view_data(self):
        rows = self.cursor.execute("SELECT * from users").fetchall()
        for row in rows:
            print(f"phone-number: {row[0]}\n----- name: {row[2]}---- surname: {row[3]}----"
                  f"email: {row[4]}---- password_salt: {row[5]}---- password: \n{row[1]}"
                  f"---- key_salt: {row[6]}---- name_nonce: {row[7]}---- surname_nonce: {row[8]}"
                  f"---- email_nonce: {row[9]}")
        rows = self.cursor.execute("SELECT * FROM messages").fetchall()
        for row in rows:
            print(f"id: {row[0]} ---- sender: {row[1]} ---- receiver: {row[2]} ---- content: {row[3]} "
                  f"---- timestamp: {row[4]}")
