from base_de_datos import Db
import os

class App:
    def __init__(self):
        self.db = Db()
        self.current_user = None

    def start(self):
        while True:
            print("¿Que quieres hacer?\n1) Iniciar sesión\n 2) Registrárse")
            result = input()
            if result not in (1, 2):
                os.system("cls")
                continue
            if result == 1:
                if self.pedir_contrasena():
                    break
                os.system("cls")
                continue
        while True:
            ...

    def pedir_contrasena(self):
        user = input("Introduzca su usuario: ")
        password = input("Introduzca su contraseña: ")
        if self.db.validate_user(user, password):
            self.current_user = user
            return True
        return False


