import os
import subprocess
import cryptography.exceptions
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
import base64
import subprocess


class CryptoBro:
    ####################### SCRYPT #######################
    @staticmethod
    def create_password(password: str) -> (str, str):
        """ Generates the password_token that is going to be stored in the database"""
        salt = os.urandom(16)  # Generates a random salt for the user
        kdf = Scrypt(
            salt=salt,
            length=256,
            n=2 ** 16,
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
            n=2 ** 16,
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
    def generate_private_key_and_public_key(self, password, telephone_number):
        os.mkdir(f"./Certificados/Usuarios/{telephone_number}")

        password = bytes(password, encoding="utf8")
        # We generate the private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        with open(f"./Certificados/Usuarios/{telephone_number}/{telephone_number}-key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password),
            ))

        # Generar signing request
        self.generate_csr(private_key, telephone_number)
        self.generate_pem(telephone_number)

    @staticmethod
    def generate_csr(private_key, telephone_number):
        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "MADRID"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, telephone_number),
            x509.NameAttribute(NameOID.COMMON_NAME, "meswap.es"),
        ])).sign(private_key, hashes.SHA256())

        with open(f"./Certificados/MeSwap/Solicitudes/{telephone_number}-csr.pem", "wb") as file:
            file.write(csr.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def generate_pem(telephone_number):
        original_working_directory = os.getcwd()

        # Change the working directory
        os.chdir("./Certificados/MeSwap/")

        password = input("Introduce la contraseña: ")

        with open("./serial", "rb") as file:
            file_data = file.read().decode("utf-8")

        os.system(f"openssl ca -in ./solicitudes/{telephone_number}-csr.pem -notext -config "
                  f"./openssl-meswap.cnf --passin pass:{password}")

        os.system(f"cp ./nuevoscerts/{file_data[:-1]}.pem "
                  f"../Usuarios/{telephone_number}/{telephone_number}-cert.pem")

        os.chdir(original_working_directory)


    @staticmethod
    def get_public_key_from_certificate(telephone_number):
        with open(f"./Certificados/Usuarios/{telephone_number}/{telephone_number}-cert.pem", "rb") as pem_file:
            pem_data = pem_file.read()

        cert = x509.load_pem_x509_certificate(pem_data)

        public_key = cert.public_key()

        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return base64.encodebytes(pem_public).decode("utf8")

    @staticmethod
    def verify_public_key(telephone_number):
        original_working_directory = os.getcwd()

        # Change the working directory
        os.chdir("./Certificados/MeSwap/")

        # Copiamos en una variable la cadena de certificaión, que solo es la propia app
        ruta_cad_cert = './meswap.pem'
        # Copiamos en una variable la certificación firmada (por AC2 y AC1)
        ruta_cert_firm = f'../Usuarios/{telephone_number}/{telephone_number}-cert.pem'

        # Comando de openssl para verificar el certificado
        comando_openssl = f"openssl verify -CAfile {ruta_cad_cert} {ruta_cert_firm}"
        ver_comando = f"openssl x509 -in ../Usuarios/{telephone_number}/{telephone_number}-cert.pem -text -noout"

        # Gracias a subprocess el comando se ejecuta en la terminal y leemos el output de este
        verif_firm = subprocess.run(comando_openssl, shell=True, capture_output=True, text=True)
        ver_cert = subprocess.run(ver_comando, shell=True, capture_output=True, text=True)

        # Comprobamos si el resultado del comando nos da OK
        if "OK" in verif_firm.stdout:
            print("Verificación de Certificado exitosa!")
            print("Detalles del certificado:")
            # Imprimiendo por pantalla el certificado legible
            print("\n\033[96mCertificado del Criptobro:\033[0m")
            print(ver_cert.stdout)
        else:
            print("Error: verificacion del certificado no exitosa")

        print(verif_firm.stdout)

        os.chdir(original_working_directory)

    def generate_encrypted_key(self, telephone_number1, telephone_number2) -> (str, str):
        """ Function that generates an encrypted key for interchange of messages"""
        # We generate a 32 bytes key for the simmentric encryption
        public_key1 = self.get_public_key_from_certificate(telephone_number1)
        public_key2 = self.get_public_key_from_certificate(telephone_number2)

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
    def decrypt_encrypted_key(telephone_number: str, encrypted_key: str, password: str):
        """ Decrypt a key given the private key """
        with open(f"./Certificados/Usuarios/{telephone_number}/{telephone_number}-key.pem", "rb") as file:
            file_data = file.read()

        password = bytes(password, encoding="utf8")

        private_key = load_pem_private_key(
            file_data,
            password
        )

        encrypted_key = base64.decodebytes(bytes(encrypted_key, encoding="utf8"))

        encrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.encodebytes(encrypted_key).decode("utf8")
