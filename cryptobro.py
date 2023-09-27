import os

import cryptography.exceptions
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64


class Crypto_bro:
    @staticmethod
    def create_password(password: str) -> (str, str):
        """ Generates the password_token that is going to be stored in the database """
        salt = os.urandom(16)  # Generates a random salt for the user
        kdf = Scrypt(
            salt=salt,
            length=256,
            n=2**16,
            r=8,
            p=1
        )
        # Returns the salt and the password in base64
        return base64.encodebytes(salt).decode('utf8'), \
            base64.encodebytes(kdf.derive(bytes(password, encoding='utf8'))).decode('utf8')

    @staticmethod
    def verify_password(password: str, salt: str, key: str) -> bool:
        """ Verifies given a salt, a key, and a password that the password is correct"""
        # Converts the salt and the key from base 64 into bytes and the password from utf8 into bytes
        password = bytes(password, encoding='utf8')
        salt = base64.decodebytes(bytes(salt, encoding='utf8'))
        key = base64.decodebytes(bytes(key, encoding='utf8'))
        kdf = Scrypt(
            salt=salt,
            length=256,
            n=2**16,
            r=8,
            p=1
        )
        # Checks that the keys match to see if the password is valid
        try:
            kdf.verify(password, key)
        except cryptography.exceptions.InvalidKey:
            return False
        return True



