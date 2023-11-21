# Importamos esta librería para poder usar los comandos de openssl
import subprocess

# Copiamos en una variable la cadena de certificaión
ruta_cad_cert = '/home/guillermo/Escritorio/Certificados/A/certs.pem'
# Copiamos en una variable la certificación firmada (por AC2 y AC1)
ruta_cert_firm = '/home/guillermo/Escritorio/Certificados/A/Acert.pem'

# Comando de openssl para verificar el certificado
comando_openssl = f"openssl verify -CAfile {ruta_cad_cert} {ruta_cert_firm}"
ver_comando = "openssl x509 -in /home/guillermo/Escritorio/Certificados/A/Acert.pem -text -noout"

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

