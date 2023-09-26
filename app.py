from base_de_datos import Db
import sys


class App:
    def __init__(self):
        self.__db = Db()
        self.__current_user = None

    def run(self):
        self.initial_screen()
        self.main_menu()

    def initial_screen(self):
        while True:
            print("¿Que quieres hacer?\n1) Iniciar sesión\n2) Registrárse")
            result = input()
            if result not in ('1', '2'):
                continue
            if result == '1':
                if self.log_in():
                    break
                continue
            if result == '2':
                self.register()
                break

    def main_menu(self):
        while True:
            print("¿Que quieres hacer?\n1) Ver mi info\n2) Ver mensajes recibidos"
                  "\n3) Ver mensajes enviados\n4) Enviar mensaje\n5) Cerrar")
            result = input()
            if result not in ('1', '2', '3', '4', '5'):
                continue
            if result == '1':
                self.show_my_info()
                continue
            if result == '2':
                self.show_messages_received()
                continue
            if result == '3':
                self.show_messages_sent()
                continue
            if result == '4':
                self.send_message()
                continue
            if result == '5':
                break

    def log_in(self):
        phone_number = input("phone-number: ")
        password = input("password: ")
        if self.__db.validate_user(phone_number, password):
            self.__current_user = phone_number
            return True
        return False

    def register(self):
        phone_number = input("phone-number: ")
        password = input("password: ")
        name = input("name: ")
        surname = input("surname: ")
        email = input("email: ")
        self.__db.add_user(phone_number, password, name, surname, email)
        self.__current_user = phone_number

    def show_my_info(self):
        info = self.__db.find_user(self.__current_user)
        print(f"Phone-number: {info[0]}\nName: {info[2]}\nSurname: {info[3]}\nEmail: {info[4]}")
        input("Pulse cualquier letra para volver")

    def show_messages_sent(self):
        info = self.__db.find_messages_sent(self.__current_user)
        for row in info:
            print(f"Sent to {row[2]} at {row[4]}:\n{row[3]}")
        input("Pulse cualquier letra para volver")

    def show_messages_received(self):
        info = self.__db.find_messages_received(self.__current_user)
        for row in info:
            print(f"Sent by {row[1]} at {row[4]}:\n{row[3]}")
        input("Pulse cualquier letra para volver")

    def send_message(self):
        receiver = input("Destinatario: ")
        content = input("Contenido: ")
        self.__db.add_message(self.__current_user, receiver, content)
        print("Mensaje enviado correctamente")

