import sqlite3
from cryptobro import CryptoBro


class Db:
    def __init__(self):
        """ Creates the connection with the database and with the crypto functions"""
        # Connects to the database file in the project
        self.db_name = "base_de_datos.db"
        self.connection = sqlite3.connect(self.db_name)
        self.cursor = self.connection.cursor()
        # Activate the constraints for the foreign key
        self.cursor.execute("PRAGMA foreign_keys = 1")
        # Creates an instance of the class crypto bro
        self.__crypto = CryptoBro()

    def add_user(self, telephone, password, name, surname, email, private_key_password):
        """ Adds a user to the database given the correct data"""
        # Generates the salt and the password token for the user
        password_salt, password_token = self.__crypto.create_password(password)
        # Generates the key_salt and the key for the user to encrypt its data
        key_salt, key = self.__crypto.first_derive_key_from_password(password)
        private_key_encrypted, public_key = self.__crypto.generate_private_key_and_public_key(private_key_password)
        # Encrypts the data and generates a nonce for each field
        name_nonce, name = self.__crypto.encrypt_my_data(key, name)
        surname_nonce, surname = self.__crypto.encrypt_my_data(key, surname)
        email_nonce, email = self.__crypto.encrypt_my_data(key, email)
        # Stores the data into the database
        self.cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                            (telephone, password_token, name, surname, email,
                             password_salt, key_salt, name_nonce, surname_nonce, email_nonce,
                             private_key_encrypted, public_key))
        self.connection.commit()
        # Return the key for the decryption of the data
        return key

    def validate_user(self, telephone, password):
        """ Validates the log-in information of a user """
        rows = list(self.cursor.execute("SELECT telephone_number, password_token, password_salt, key_salt "
                                        "FROM users WHERE telephone_number = ?;"
                                        , (telephone,)))
        # Verify that the password is the correct one and generates the key for the decryption
        if len(rows) != 0 or self.__crypto.verify_password(password, rows[0][2], rows[0][1]):
            # If the password is right we return the key for the decryption of the data
            return self.__crypto.derive_key_from_password(rows[0][3], password)
        return False

    def find_user(self, telephone):
        """ Returns all the information from a user given its phone_number"""
        # Returns all the data stored in the database for the given phone number
        rows = list(self.cursor.execute("SELECT * FROM users WHERE telephone_number = ?;", (telephone,)))
        return rows[0]

    def add_message(self, sender, conversation_id, encrypted_content, nonce):
        """ Adds a message to the database """
        self.cursor.execute("INSERT INTO messages(sender, content, nonce, cryptobros_id) VALUES (?, ?, ?, ?);",
                            (sender, encrypted_content, nonce, conversation_id))
        self.connection.commit()

    def check_conversation(self, sender, receiver):
        """
        Function that checks if two users have talked before and return the encrypted simmetric key and the
        conversation id
        """
        # We check if they hace talked before
        rows1 = list(self.cursor.execute("SELECT * FROM cryptobros WHERE cryptobro1=? AND cryptobro2=?",
                                         (sender, receiver)))
        rows2 = list(self.cursor.execute("SELECT * FROM cryptobros WHERE cryptobro1=? AND cryptobro2=?",
                                         (receiver, sender)))
        if len(rows1) > 0:
            # We return the encrypted_key with senders public_key (case: sender -> cryptobro1)
            return rows1[0][3], rows1[0][0]
        elif len(rows2) > 0:
            # We return the encrypted_key with senders public_key (case: sender -> cryptobro2)
            return rows2[0][4], rows2[0][0]
        else:
            # If they have not talked before we add them to the cryptobros database with a random key
            # We save the public key of the sender
            public_key1 = list(self.cursor.execute("SELECT public_key FROM users WHERE telephone_number=?",
                                                   (sender,)))[0][0]
            # We save the public key of the receiver
            public_key2 = list(self.cursor.execute("SELECT public_key FROM users WHERE telephone_number=?",
                                                   (receiver,)))[0][0]

            # We generate a key for encrypting for saving it encrypted with their public keys
            key1, key2 = self.__crypto.generate_encrypted_key(public_key1, public_key2)

            # We add the sender and the receiver with their respective encrypted keys with their public_key
            self.cursor.execute("INSERT INTO cryptobros(cryptobro1, cryptobro2, key_encrypted1, key_encrypted2) "
                                "VALUES (?, ?, ?, ?)", (sender, receiver, key1, key2))
            rows = self.cursor.execute("SELECT id FROM cryptobros WHERE cryptobro1=? AND cryptobro2=?",
                                       (sender, receiver)).fetchall()
            # We return the key of the sender once it is generated
            return key1, rows[0][0]

    def get_private_key(self, user):
        """ Returns the encrypted private key of a given user"""
        return list(self.cursor.execute("SELECT private_key_encrypted FROM users WHERE telephone_number=?",
                                        (user,)))[0][0]

    def get_conversations(self, user):
        """ Returns the phone number that the user has talked to """
        rows = self.cursor.execute(
            """
            SELECT cryptobro1 AS user, cryptobro2 AS partner
            FROM cryptobros
            WHERE  cryptobro1=?
            UNION SELECT cryptobro2 AS user, cryptobro1 AS partner
            FROM cryptobros
            WHERE  cryptobro2=?;
        """, (user, user)).fetchall()

        return (row[1] for row in rows)

    def get_conversation_id(self, user1, user2):
        rows1 = list(self.cursor.execute("SELECT id FROM cryptobros WHERE cryptobro1=? AND cryptobro2=?",
                                         (user1, user2)))
        rows2 = list(self.cursor.execute("SELECT id FROM cryptobros WHERE cryptobro1=? AND cryptobro2=?",
                                         (user2, user1)))
        if len(rows1) > 0:
            # We return the encrypted_key with senders public_key (case: sender -> cryptobro1)
            return rows1[0][0]
        elif len(rows2) > 0:
            # We return the encrypted_key with senders public_key (case: sender -> cryptobro2)
            return rows2[0][0]

    def get_messages(self, conversation_id):
        """ Gets the messages given a conversation id"""
        rows = self.cursor.execute("SELECT * FROM messages WHERE cryptobros_id=?",
                                   (conversation_id,)).fetchall()
        return rows

    # THIS CODE CREATES FICTIONAL USERS THAT DO NOT REPRESENT REAL USERS SO THE CREDENTIALS DO NOT BELONG TO ANYONE
    # THEY ARE IN THE CODE ONLY FOR TESTING PURPOSES

    def populate_users(self):
        self.add_user('111111111', 'password', 'user1',
                      'user1', '1@hola.es', 'password')
        self.add_user('222222222', 'password', 'user2',
                      'user2', '2@hola.es', 'password')
        self.add_user('333333333', 'password', 'user3',
                      'user3', '3@hola.es', 'password')
        self.add_user('444444444', 'password', 'user4',
                      'user4', '4@hola.es', 'password')
        self.add_user('555555555', 'password', 'user5',
                      'user5', '5@hola.es', 'password')
        self.add_user('666666666', 'password', 'user6',
                      'user6', '6@hola.es', 'password')
        self.add_user('777777777', 'password', 'user7',
                      'user7', '7@hola.es', 'password')
        self.add_user('888888888', 'password', 'user8',
                      'user8', '8@hola.es', 'password')
        self.add_user('999999999', 'password', 'user9',
                      'user9', '9@hola.es', 'password')

    # THIS CODE IS USED TO CREATE THE DATABASE AND TO RESET IT TO AN INITIAL STATE WITH THE FICTIONAL USERS
    # SHOWN IN THE CODE BEFORE
    def reset_db(self):
        """ Resets the database to initial state with some fictional users and messages"""
        self.delete_db()
        self.create_db()
        self.populate_users()

    def create_db(self):
        """ Creates the tables of the database: users and messages"""
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
                            "email_nonce CHAR(17),"
                            "private_key_encrypted CHAR(2533),"
                            "public_key CHAR(612)"
                            ");")

        self.cursor.execute(""
                            "CREATE TABLE cryptobros ("
                            "id INTEGER PRIMARY KEY,"
                            "cryptobro1 CHAR(9) NOT NULL,"
                            "cryptobro2 CHAR(9) NOT NULL,"
                            "key_encrypted1 CHAR(349),"
                            "key_encrypted2 CHAR(349),"
                            "UNIQUE (cryptobro1, cryptobro2),"
                            "FOREIGN KEY(cryptobro1) REFERENCES users(telephone_number),"
                            "FOREIGN KEY(cryptobro2) REFERENCES users(telephone_number)"
                            ");")

        self.cursor.execute(""
                            "CREATE TABLE messages ("
                            "id INTEGER PRIMARY KEY,"
                            "sender CHAR(9) NOT NULL,"
                            "content VARCHAR2(512) NOT NULL,"
                            "nonce CHAR(17) NOT NULL,"
                            "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
                            "cryptobros_id INTEGER NOT NULL,"
                            "FOREIGN KEY(cryptobros_id) REFERENCES cryptobros(id),"
                            "FOREIGN KEY(sender) REFERENCES users(telephone_number)"
                            ");")

    def delete_db(self):
        """ Deletes the tables from the database. Useful for restarting it"""
        self.cursor.execute("DROP TABLE messages;")
        self.cursor.execute("DROP TABLE cryptobros;")
        self.cursor.execute("DROP TABLE users;")

    def view_data(self):
        rows = self.cursor.execute("SELECT * from users").fetchall()
        for row in rows:
            print(f"phone-number: {row[0]}\n---- name: {row[2]}---- surname: {row[3]}----"
                  f" email: {row[4]}---- password_salt: {row[5]}---- password: \n{row[1]}"
                  f"---- key_salt: {row[6]}---- name_nonce: {row[7]}---- surname_nonce: {row[8]}"
                  f"---- email_nonce: {row[9]}")
        rows = self.cursor.execute("SELECT * FROM messages").fetchall()
        for row in rows:
            print(f"id: {row[0]} ---- sender: {row[1]} ---- receiver: {row[2]} ---- content: {row[3]} "
                  f"---- timestamp: {row[4]}")
