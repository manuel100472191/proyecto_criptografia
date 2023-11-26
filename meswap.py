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

        password_frame = ttk.Frame(self.root, padding=10)
        self.pages["password"] = password_frame

        # Creating the send message frame
        send_frame = ttk.Frame(self.root, padding=10)
        self.pages["send"] = send_frame
        self.add_send_message_frame(send_frame)

        # We start with the frame log-in
        self.show_page("login")

        # We start he main loop for the app
        self.root.mainloop()

    def add_login_frame(self, frame):
        """ Creates the login frame interface """
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
        """ Creates the register frame interface """
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
        password_private_key_label = ttk.Label(frame, text="Password for private key:")
        self.password_private_key_entry = ttk.Entry(frame, show="*")
        repeat_password_private_key = ttk.Label(frame, text="Repeat Password:")
        self.repeat_password_private_key_entry = ttk.Entry(frame, show="*")
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
        password_private_key_label.grid(row=6, column=0, pady=10)
        self.password_private_key_entry.grid(row=6, column=1, pady=10)
        repeat_password_private_key.grid(row=7, column=0, pady=10)
        self.repeat_password_private_key_entry.grid(row=7, column=1, pady=10)
        register_button.grid(row=8, column=0, columnspan=2, pady=10)

    def add_main_frame(self, frame):
        """ Creating the main frame with four buttons one for each action """
        self.info_button = ttk.Button(frame, text="My info", command=lambda: self.add_info_frame())
        self.rec_mess_button = ttk.Button(frame, text="Show conversations",
                                          command=lambda: self.add_conversations_frame())
        self.send_mess_button = ttk.Button(frame, text="Send messages", command=lambda: self.show_page("send"))

        self.info_button.grid(row=0, column=0, padx=30, pady=10)
        self.rec_mess_button.grid(row=1, column=0, padx=30, pady=10)
        self.send_mess_button.grid(row=2, column=0, padx=30, pady=10)

    def add_info_frame(self):
        """ Creates my info frame interface"""
        info_frame = ttk.Frame(self.root, padding=10)
        self.pages["info"] = info_frame

        # Decrypt the data received with the key of the current session
        info = self.__db.find_user(self.__current_user)
        phone_number = info[0]
        # We use the key, the nonce that is stored in the database and the info for the decryption
        name = self.__crypto.decrypt_my_data(self.__key, info[7], info[2])
        surname = self.__crypto.decrypt_my_data(self.__key, info[8], info[3])
        email = self.__crypto.decrypt_my_data(self.__key, info[9], info[4])

        # After the decryption of the data we can show it in the frame
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

    def add_conversations_frame(self):
        """ Creates the messages frame interface """
        # First check if the page already set so if it does exist it can be updated with new messages
        if self.pages.get("conversation") is not None:
            frame = self.pages["conversation"]
            frame.destroy()
            del self.pages["conversation"]
            self.add_conversations_frame()
        else:
            # If the page does not exist we find the messages sent and show them on the screen
            info = self.__db.get_conversations(self.__current_user)
            conversation_frame = ttk.Frame(self.root, padding=10)
            self.pages["conversation"] = conversation_frame
            for user in info:
                conversation_id = self.__db.get_conversation_id(self.__current_user, user)
                print(user, conversation_id)
                ttk.Button(conversation_frame, text=f"{user}",
                           command=lambda u=user, cid=conversation_id: self.add_password_frame(cid, u)).pack(pady=10)
            ttk.Button(conversation_frame, text="Back", command=lambda: self.show_page("main")).pack()
            self.show_page("conversation")

    def add_password_frame(self, conversation_id, user):
        print(f"conversation_id = {conversation_id}. user = {user}\n")
        if self.pages.get("password") is not None:
            frame = self.pages["password"]
            frame.destroy()
            del self.pages["password"]
            self.add_conversations_frame()
        else:
            frame = ttk.Frame(self.root, padding=10)
            self.pages["password"] = frame

            password_label = ttk.Label(frame, text="Password:")
            self.password_entry_4 = ttk.Entry(frame, show="*")

            password_label.grid(row=0, column=0, pady=10)
            self.password_entry_4.grid(row=0, column=1, columnspan=2)
            ttk.Button(frame, text="Go", command=lambda: self.add_messages_frame(
                conversation_id, self.password_entry_4.get(), user
            )).grid(row=3, column=0, columnspan=2, pady=10)

            self.show_page("password")

    def add_messages_frame(self, conversation_id, password, user):
        """ Creates the message from a specific conversation frame interface"""
        # First check if the page already set so if it does exist it can be updated with new messages
        if self.pages.get("messages") is not None:
            frame = self.pages["messages"]
            frame.destroy()
            del self.pages["messages"]
            self.add_messages_frame(conversation_id, password, user)
        else:
            # If the page does not exist we find the messages received and show them on the screen
            info = self.__db.get_messages(conversation_id)
            frame = ttk.Frame(self.root, padding=10)
            self.pages["messages"] = frame
            encrypted_key = self.__db.check_conversation(self.__current_user, user)[0]
            key = self.__crypto.decrypt_encrypted_key(self.__current_user, encrypted_key, password)
            for row in info:
                content = self.__crypto.decrypt_my_data(key, row[3], row[2])
                ttk.Label(frame, text=f"Sent by {row[1]} at {row[4]}:\n{content}").pack(pady=10)
            # We add one button for going back and one for updating the messages received
            ttk.Button(frame, text="Back", command=lambda: self.add_conversations_frame()).pack()
            ttk.Button(frame, text="Update",
                       command=lambda: self.add_messages_frame(conversation_id, password, user)).pack()
            self.show_page("messages")

    def add_send_message_frame(self, frame):
        """ Creates the send message frame where with two entries one for the receiver phone number and the otehr
        for the content of the message"""
        ttk.Label(frame, text="To:").grid(row=0, column=0, pady=0)
        self.receiver_entry = ttk.Entry(frame)
        self.content = tk.Text(frame, width=40, height=7, bg="white", fg="black", highlightcolor="white")
        ttk.Label(frame, text="Password:").grid(row=2, column=0, pady=0)
        self.password_entry_3 = ttk.Entry(frame, show="*")
        self.receiver_entry.grid(row=0, column=1, pady=10)
        self.content.grid(row=1, column=0, columnspan=2, pady=10)
        self.password_entry_3.grid(row=2, column=1, columnspan=2, pady=10)
        ttk.Button(frame, text="Send", command=self.send_message).grid(row=3, column=0, columnspan=2, pady=10)

    def send_message(self):
        """ Creates a messages from the inputs of the send message frame and adds them to the database"""
        receiver = self.receiver_entry.get()
        content = self.content.get("1.0", tk.END)
        password = self.password_entry_3.get()
        try:
            # We get the key for encrypting the conversation from the database
            encrypted_key, conversation_id = self.__db.check_conversation(self.__current_user, receiver)
            key = self.__crypto.decrypt_encrypted_key(self.__current_user, encrypted_key, password)
            nonce, content = self.__crypto.encrypt_my_data(key, content)
            self.__db.add_message(self.__current_user, conversation_id, content, nonce)
            self.show_page("main")

        except sqlite3.OperationalError or ValueError as error:
            print(error)
            self.receiver_entry.delete(0, tk.END)
            self.content.delete("1.0", tk.END)
            self.password_entry_3.delete(0, tk.END)

    def show_page(self, page_name):
        """ Changes the current view of the frame to the one in the input"""
        for page in self.pages.values():
            page.grid_forget()

        self.pages[page_name].grid(row=0, column=0)

    def login(self):
        """ Checks that the info that the credentials of the log in frame are correct"""
        phone_number = self.phone_entry.get()
        password = self.password_entry.get()
        key = self.__db.validate_user(phone_number, password)
        # If the credentials are right we save the key for the current session and go the main frame
        if key is not False:
            self.__current_user = phone_number
            self.__key = key
            self.show_page("main")

    def register(self):
        """ We create a new user in the database with the inputs in the register frame"""
        phone_number = self.phone_entry_2.get()
        password = self.password_entry_2.get()
        password2 = self.repeat_password_entry.get()
        name = self.name_entry.get()
        surname = self.surname_entry.get()
        email = self.email_entry.get()
        private_key_pass = self.password_private_key_entry.get()
        private_key_pass2 = self.repeat_password_private_key_entry.get()
        # If the two passwords are the same we create the user and set the current user
        # and the key to the current user and key
        if password == password2 and private_key_pass == private_key_pass2:
            self.__key = self.__db.add_user(phone_number, password, name, surname, email, private_key_pass)
            self.__current_user = phone_number
            self.show_page("main")
        else:
            # If the inputs are wrong we reset the entries
            self.phone_entry_2.delete(0, tk.END)
            self.password_entry_2.delete(0, tk.END)
            self.repeat_password_entry.delete(0, tk.END)
            self.name_entry.delete(0, tk.END)
            self.surname_entry.delete(0, tk.END)
            self.email_entry.delete(0, tk.END)
            self.password_private_key_entry.delete(0, tk.END)
            self.repeat_password_private_key_entry.delete(0, tk.END)


