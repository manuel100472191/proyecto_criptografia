import os

import cryptography.exceptions
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64


class CryptoBro:
    ####################### SCRYPT #######################
    @staticmethod
    def create_password(password: str) -> (str, str):
        """ Generates the password_token that is going to be stored in the database"""
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

    ####################### PBKDF2 #######################
    @staticmethod
    def first_derive_key_from_password(password: str):
        """ Generates the key with the password for the first time"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = kdf.derive(bytes(password, encoding="utf8"))
        return base64.encodebytes(salt).decode("utf8"), base64.encodebytes(key).decode("utf8")

    @staticmethod
    def derive_key_from_password(salt: str, password: str):
        """ Derives a key given a salt and a password"""
        salt = base64.decodebytes(bytes(salt, encoding='utf8'))
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = kdf.derive(bytes(password, encoding="utf8"))
        return base64.encodebytes(key).decode("utf8")

    ####################### CHACHA20POLY #######################
    @staticmethod
    def encrypt_my_data(key: str, data: str):
        """ Encrypts data given a key and returns the nonce"""
        key = base64.decodebytes(bytes(key, encoding="utf8"))
        data = bytes(data, encoding="utf8")
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ct = chacha.encrypt(nonce, data, None)

        return base64.encodebytes(nonce).decode("utf8"), base64.encodebytes(ct).decode("utf8")

    @staticmethod
    def decrypt_my_data(key, nonce, data):
        """ Decrypts and authenticates data given key and a nonce"""
        key = base64.decodebytes(bytes(key, encoding="utf8"))
        data = base64.decodebytes(bytes(data, encoding="utf8"))
        nonce = base64.decodebytes(bytes(nonce, encoding="utf8"))

        chacha = ChaCha20Poly1305(key)
        result = chacha.decrypt(nonce, data, None)
        return result.decode("utf8")

    ####################### RSA #######################
    @staticmethod
    def generate_private_key_and_public_key(password):
        password = bytes(password, encoding="utf8")
        # We generate the private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # We generate the public key
        public_key = private_key.public_key()
        # Serializing the private key and encrypting it
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )
        # Serializing the public key without encryption
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return base64.encodebytes(pem_private).decode("utf8"), base64.encodebytes(pem_public).decode("utf8")

    @staticmethod
    def generate_encrypted_key(public_key1, public_key2) -> (str, str):
        """ Function that generates an encrypted key for interchange of messages"""
        # We generate a 32 bytes key for the simmentric encryption
        key = os.urandom(32)

        # We encrypt the key with the public key of user 1
        public_key1 = base64.decodebytes(bytes(public_key1, encoding="utf8"))
        public_key1 = serialization.load_pem_public_key(public_key1)
        encrypted_key1 = public_key1.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # We encrypt the key with the public key of user 2
        public_key2 = base64.decodebytes(bytes(public_key2, encoding="utf8"))
        public_key2 = serialization.load_pem_public_key(public_key2)
        encrypted_key2 = public_key2.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.encodebytes(encrypted_key1).decode("utf8"), base64.encodebytes(encrypted_key2).decode("utf8")

    @staticmethod
    def decrypt_encrypted_key(private_key: str, encrypted_key: str, password: str):
        """ Decrypt a key given the private key """
        private_key = base64.decodebytes(bytes(private_key, encoding="utf8"))
        password = bytes(password, encoding="utf8")
        encrypted_key = base64.decodebytes(bytes(encrypted_key, encoding="utf8"))

        private_key = serialization.load_pem_private_key(
            private_key,
            password
        )

        encrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.encodebytes(encrypted_key).decode("utf8")








