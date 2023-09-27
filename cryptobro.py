import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64

class Crypto_bro:
    def create_password(self, password: str):
        salt = os.urandom(16)  # Crea salt de 16 bytes
        kdf = Scrypt(
            salt=salt,
            length=256,
            n=2**16,
            r=8,
            p=1
        )
        return base64.encodebytes(salt).decode('utf8'), \
            base64.encodebytes(kdf.derive(bytes(password, encoding='utf8'))).decode('utf8')

    def verify_password(self, password: str, salt: str, key: str):
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
        try:
            kdf.verify(password, key)
        except:
            return False
        return True


