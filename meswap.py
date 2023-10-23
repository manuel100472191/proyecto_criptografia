import sqlite3
import tkinter as tk
from tkinter import ttk
from base_de_datos import Db
from cryptobro import CryptoBro


class MeSwap:
    def __init__(self):
        # We create a connection to the database
        self.__db = Db()
        # The variable current user saves the phone number of the user that has log in
        self.__current_user = None
        # The variable key saves the key of the user for the current session
        self.__key = None
        # We create an instance of the class cryptobro that has the interface for the criptographic functions
        self.__crypto = CryptoBro()

        # We create the interface root from the class tkinter and give it some properties
        self.root = tk.Tk()
        self.root.title('MeSwap')
        self.root.resizable(width=False, height=False)

        style = ttk.Style()
        style.theme_use("clam")

        # We create a dictionery that will store the different pages of the app
        self.pages = {}

        # Creating the log-in frame
        login_frame = ttk.Frame(self.root, padding=10)
        self.pages["login"] = login_frame
        self.add_login_frame(login_frame)

        # Creating the register frame
        register_frame = ttk.Frame(self.root, padding=10)
        self.pages["register"] = register_frame
        self.add_register_frame(register_frame)

        # Creating the main frame
        main_frame = ttk.Frame(self.root, padding=10)
        self.pages["main"] = main_frame
        self.add_main_frame(main_frame)

        # Creating the send message frame
        send_frame = ttk.Frame(self.root, padding=10)
        self.pages["send"] = send_frame
        self.add_send_message_frame(send_frame)

        # We start with the frame log-in
        self.show_page("login")

        # We start he main loop for the app
        self.root.mainloop()

    def add_login_frame(self, frame):
        # We create the login frame with the fields
        phone_label = ttk.Label(frame, text="Phone Number:")
        self.phone_entry = ttk.Entry(frame)
        password_label = ttk.Label(frame, text="Password:")
        self.password_entry = ttk.Entry(frame, show="*")
        login_button = ttk.Button(frame, text="Login", command=self.login)
        register_button = ttk.Button(frame, text="Register", command=lambda: self.show_page("register"))

        phone_label.grid(row=0, column=0, pady=10)
        self.phone_entry.grid(row=0, column=1, pady=10)
        password_label.grid(row=1, column=0, pady=10)
        self.password_entry.grid(row=1, column=1, pady=10)
        login_button.grid(row=2, column=0, columnspan=2, pady=10)
        register_button.grid(row=3, column=0, columnspan=2, pady=10)

    def add_register_frame(self, frame):
        # We create the different fields for the register
        phone_label = ttk.Label(frame, text="Phone Number:")
        self.phone_entry_2 = ttk.Entry(frame)
        password_label = ttk.Label(frame, text="Password:")
        self.password_entry_2 = ttk.Entry(frame, show="*")
        repeat_password_label = ttk.Label(frame, text="Repeat Password:")
        self.repeat_password_entry = ttk.Entry(frame, show="*")
        name_label = ttk.Label(frame, text="Name:")
        self.name_entry = ttk.Entry(frame)
        surname_label = ttk.Label(frame, text="Surname:")
        self.surname_entry = ttk.Entry(frame)
        email_label = ttk.Label(frame, text="Email:")
        self.email_entry = ttk.Entry(frame)
        register_button = ttk.Button(frame, text="Register", command=self.register)

        phone_label.grid(row=0, column=0, pady=10)
        self.phone_entry_2.grid(row=0, column=1, pady=10)
        password_label.grid(row=1, column=0, pady=10)
        self.password_entry_2.grid(row=1, column=1, pady=10)
        repeat_password_label.grid(row=2, column=0, pady=10)
        self.repeat_password_entry.grid(row=2, column=1, pady=10)
        name_label.grid(row=3, column=0, pady=10)
        self.name_entry.grid(row=3, column=1, pady=10)
        surname_label.grid(row=4, column=0, pady=10)
        self.surname_entry.grid(row=4, column=1, pady=10)
        email_label.grid(row=5, column=0, pady=10)
        self.email_entry.grid(row=5, column=1, pady=10)
        register_button.grid(row=6, column=0, columnspan=2, pady=10)

    def add_main_frame(self, frame):
        self.info_button = ttk.Button(frame, text="My info", command=lambda: self.add_info_frame())
        self.rec_mess_button = ttk.Button(frame, text="Show messages received",
                                          command=lambda: self.add_messages_received_frame())
        self.sent_mess_button = ttk.Button(frame, text="Show messages sent",
                                           command=lambda: self.add_messages_sent_frame())
        self.send_mess_button = ttk.Button(frame, text="Send messages", command=lambda: self.show_page("send"))

        self.info_button.grid(row=0, column=0, padx=30, pady=10)
        self.rec_mess_button.grid(row=1, column=0, padx=30, pady=10)
        self.sent_mess_button.grid(row=2, column=0, padx=30, pady=10)
        self.send_mess_button.grid(row=3, column=0, padx=30, pady=10)

    def add_info_frame(self):
        info_frame = ttk.Frame(self.root, padding=10)
        self.pages["info"] = info_frame

        # Decrypt the data received
        info = self.__db.find_user(self.__current_user)
        phone_number = info[0]
        name = self.__crypto.decrypt_my_data(self.__key, info[7], info[2])
        surname = self.__crypto.decrypt_my_data(self.__key, info[8], info[3])
        email = self.__crypto.decrypt_my_data(self.__key, info[9], info[4])

        phone_label = ttk.Label(info_frame, text=f"Phone Number: {phone_number}")
        name_label = ttk.Label(info_frame, text=f"Name: {name}")
        surname_label = ttk.Label(info_frame, text=f"Surname: {surname}")
        email_label = ttk.Label(info_frame, text=f"Email: {email}")
        back_button = ttk.Button(info_frame, text="Back", command=lambda: self.show_page("main"))

        phone_label.grid(row=0, column=0, pady=10)
        name_label.grid(row=1, column=0, pady=10)
        surname_label.grid(row=2, column=0, pady=10)
        email_label.grid(row=3, column=0, pady=10)
        back_button.grid(row=4, column=0, pady=10)
        self.show_page("info")

    def add_messages_sent_frame(self):
        try:
            frame = self.pages["sent"]
            self.show_page("sent")
        except KeyError:
            info = self.__db.find_messages_sent(self.__current_user)
            sent_frame = ttk.Frame(self.root, padding=10)
            self.pages["sent"] = sent_frame
            for row in info:
                ttk.Label(sent_frame, text=f"Sent to {row[2]} at {row[4]}:\n{row[3]}").pack(pady=10)
            ttk.Button(sent_frame, text="Back", command=lambda: self.show_page("main")).pack()
            self.show_page("sent")

    def add_messages_received_frame(self):
        if self.pages.get("received") is not None:
            frame = self.pages["received"]
            frame.destroy()
            del self.pages["received"]
            self.add_messages_received_frame()
        else:
            info = self.__db.find_messages_received(self.__current_user)
            received_frame = ttk.Frame(self.root, padding=10)
            self.pages["received"] = received_frame
            for row in info:
                ttk.Label(received_frame, text=f"Sent by {row[1]} at {row[4]}:\n{row[3]}").pack(pady=10)
            ttk.Button(received_frame, text="Back", command=lambda: self.show_page("main")).pack()
            ttk.Button(received_frame, text="Update", command=self.add_messages_received_frame).pack()
            self.show_page("received")

    def add_send_message_frame(self, frame):
        ttk.Label(frame, text="To:").grid(row=0, column=0, pady=0)
        self.receiver_entry = ttk.Entry(frame)
        self.content = ttk.Entry(frame)
        self.receiver_entry.grid(row=0, column=1, pady=10)
        self.content.grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(frame, text="Send", command=self.send_message).grid(row=2, column=0, columnspan=2, pady=10)

    def send_message(self):
        receiver = self.receiver_entry.get()
        content = self.content.get()
        try:
            self.__db.add_message(self.__current_user, receiver, content)
            self.show_page("main")

        except sqlite3.OperationalError:
            self.receiver_entry.delete(0, tk.END)
            self.content.delete(0, tk.END)

    def show_page(self, page_name):
        for page in self.pages.values():
            page.grid_forget()

        self.pages[page_name].grid(row=0, column=0)

    def login(self):
        phone_number = self.phone_entry.get()
        password = self.password_entry.get()
        key = self.__db.validate_user(phone_number, password)
        if key is not False:
            self.__current_user = phone_number
            self.__key = key
            self.show_page("main")

    def register(self):
        phone_number = self.phone_entry_2.get()
        password = self.password_entry_2.get()
        password2 = self.repeat_password_entry.get()
        name = self.name_entry.get()
        surname = self.surname_entry.get()
        email = self.email_entry.get()
        if password == password2:
            self.__key = self.__db.add_user(phone_number, password, name, surname, email)
            self.__current_user = phone_number
            self.show_page("main")
        else:
            self.phone_entry_2.delete(0, tk.END)
            self.password_entry_2.delete(0, tk.END)
            self.repeat_password_entry.delete(0, tk.END)
            self.name_entry.delete(0, tk.END)
            self.surname_entry.delete(0, tk.END)
            self.email_entry.delete(0, tk.END)


