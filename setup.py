# Importamos esta librería para poder usar los comandos de openssl
import subprocess
import os
import shutil
from base_de_datos import Db


def delete_all_files_in_directory(directory_path):
    try:
        # Get a list of all items in the directory
        items = os.listdir(directory_path)

        for item in items:
            item_path = os.path.join(directory_path, item)

            if os.path.isfile(item_path):
                # If it's a file, delete it
                os.remove(item_path)
                print(f"File '{item_path}' has been deleted.")
            elif os.path.isdir(item_path):
                # If it's a directory, delete it and its contents
                shutil.rmtree(item_path)
                print(f"Directory '{item_path}' and its contents have been deleted.")

        print(f"All files and directories in '{directory_path}' have been deleted.")
    except Exception as e:
        print(f"Error: {e}")


def delete_file(file_path):
    try:
        os.remove(file_path)
    except Exception as e:
        print(e)


def main():
    delete_all_files_in_directory("./Certificados/Usuarios/")
    delete_all_files_in_directory("./Certificados/MeSwap/nuevoscerts")
    delete_all_files_in_directory("./Certificados/MeSwap/privado/")
    delete_all_files_in_directory("./Certificados/MeSwap/solicitudes")
    delete_file("./Certificados/MeSwap/index.txt.attr")
    delete_file("./Certificados/MeSwap/index.txt.attr")
    delete_file("./Certificados/MeSwap/index.txt.old")
    delete_file("./Certificados/MeSwap/serial.old")
    delete_file("./Certificados/MeSwap/serial")
    delete_file("./Certificados/MeSwap/index.txt")
    delete_file("./Certificados/MeSwap/meswap.pem")

    os.chdir(f"./Certificados/MeSwap/")
    os.system(f"echo '01' > serial")
    os.system(f"touch index.txt")
    os.system(f"openssl req -x509 -newkey rsa:2048 -days 360 -out meswap.pem -outform PEM -config openssl-meswap.cnf")
    os.chdir(f"../..")
    db = Db()
    db.reset_db()


if __name__ == "__main__":
    main()




