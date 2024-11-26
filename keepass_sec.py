from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import json
import os
from colorama import Fore, Style, init
from getpass import getpass
import base64
import hashlib

# Inicializar colorama
init(autoreset=True)

# Derivar una clave de 32 bytes a partir de la clave maestra usando PBKDF2
def derivar_clave_maestra(clave_maestra):
    # Usamos PBKDF2 con SHA256 para derivar una clave de 32 bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"salt",  # Salt aleatorio (puedes cambiar esto)
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(clave_maestra.encode()))

# Generar y guardar una clave maestra cifrada
def generar_clave_maestra():
    clave_maestra = getpass(Fore.WHITE + "Introduce tu clave maestra (mínimo 8 caracteres): ")
    while len(clave_maestra) < 8:
        print(Fore.RED + "La clave maestra debe tener al menos 8 caracteres.")
        clave_maestra = getpass(Fore.WHITE + "Introduce tu clave maestra: ")
    
    # Derivar la clave Fernet a partir de la clave maestra
    clave_fernet = derivar_clave_maestra(clave_maestra)
    
    # Guardar la clave maestra cifrada (para futuras verificaciones)
    with open("clave_maestra.key", "wb") as clave_file:
        clave_file.write(clave_maestra.encode())

    # Guardar la clave de Fernet para su uso posterior
    with open("clave_fernet.key", "wb") as fernet_file:
        fernet_file.write(clave_fernet)

# Cargar y verificar la clave maestra
def cargar_clave_maestra():
    with open("clave_maestra.key", "rb") as clave_file:
        clave_maestra = clave_file.read()
    return clave_maestra.decode()

# Cargar la clave de Fernet desde el archivo
def cargar_clave_fernet():
    with open("clave_fernet.key", "rb") as fernet_file:
        clave_fernet = fernet_file.read()
    return clave_fernet

# Cifrar contraseña
def cifrar_contraseña(contraseña, clave):
    fernet = Fernet(clave)
    return fernet.encrypt(contraseña.encode())

# Descifrar contraseña
def descifrar_contraseña(contraseña_cifrada, clave):
    fernet = Fernet(clave)
    return fernet.decrypt(contraseña_cifrada).decode()

# Guardar una contraseña
def guardar_contraseña(sitio, usuario, contraseña, clave_fernet):
    contraseñas = cargar_contraseñas()
    contraseña_cifrada = cifrar_contraseña(contraseña, clave_fernet)
    contraseñas[sitio] = {"usuario": usuario, "contraseña": contraseña_cifrada.decode()}
    with open("contraseñas.json", "w") as archivo:
        json.dump(contraseñas, archivo)

# Cargar todas las contraseñas guardadas
def cargar_contraseñas():
    if os.path.exists("contraseñas.json"):
        with open("contraseñas.json", "r") as archivo:
            return json.load(archivo)
    return {}

# Mostrar todas las contraseñas descifradas
def mostrar_contraseñas(clave_fernet):
    contraseñas = cargar_contraseñas()
    if not contraseñas:
        print(Fore.YELLOW + "No hay contraseñas guardadas.")
    else:
        for sitio, datos in contraseñas.items():
            usuario = datos["usuario"]
            contraseña = descifrar_contraseña(datos["contraseña"].encode(), clave_fernet)
            print(f"{Fore.CYAN}Sitio: {sitio}, {Fore.GREEN}Usuario: {usuario}, {Fore.RED}Contraseña: {contraseña}")

# Menú del gestor
def main():
    # Verifica si ya existe la clave maestra o la clave de Fernet
    if not os.path.exists("clave_maestra.key") or not os.path.exists("clave_fernet.key"):
        generar_clave_maestra()
    
    # Pide la clave maestra para acceso futuro
    clave_maestra = getpass(Fore.WHITE + "Introduce tu clave maestra para acceder al gestor: ")

    try:
        # Verificar si la clave maestra es correcta
        clave_guardada = cargar_clave_maestra()
        if clave_maestra != clave_guardada:
            print(Fore.RED + "Clave maestra incorrecta. Acceso denegado.")
            return
    except:
        print(Fore.RED + "No se pudo cargar la clave maestra.")
        return
    
    # Derivar la clave de Fernet desde la clave maestra
    clave_fernet = derivar_clave_maestra(clave_maestra)
    
    # Luego de validación, carga el resto del gestor
    while True:
        print(Fore.MAGENTA + "\nGestor de Contraseñas")
        print(Fore.YELLOW + "1. Guardar nueva contraseña")
        print(Fore.YELLOW + "2. Mostrar contraseñas guardadas")
        print(Fore.YELLOW + "3. Salir")
        opcion = input(Fore.WHITE + "Selecciona una opción: ")
        
        if opcion == "1":
            sitio = input(Fore.WHITE + "Sitio web o nombre del servicio: ")
            usuario = input(Fore.WHITE + "Nombre de usuario/email: ")
            contraseña = input(Fore.WHITE + "Contraseña: ")
            guardar_contraseña(sitio, usuario, contraseña, clave_fernet)
            print(Fore.GREEN + "Contraseña guardada con éxito.")
        
        elif opcion == "2":
            mostrar_contraseñas(clave_fernet)
        
        elif opcion == "3":
            print(Fore.RED + "Saliendo...")
            break
        else:
            print(Fore.RED + "Opción no válida.")

if __name__ == "__main__":
    main()
