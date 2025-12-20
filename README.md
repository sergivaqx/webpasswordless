# **Trabajo Final Análisis de Malware**

Codigo fuente del trabajo final para la maestria de análisis de malware. Este enlace lleva a un video de su funcionamiento: *https://youtu.be/nwjALwAeY3I*

1. Estructura
	- Framework: Django 5.0+
	- BD: PostgreSQL
	- Librerías Clave:
		- cryptography: Para cifrado AES (Fernet).
		- fido2: Para manejar el protocolo WebAuthn (Passkeys).
		- psycopg: Driver de PostgreSQL.

2. Instalación
	- Instalar las librerias usando pip install:
		- django 
		- psycopg[binary] 
		- cryptography 
		- fido2 
		- django-extensions 
		- python-dotenv
	- Ejecutar los siguientes comandos en la consola, dentro de la carpeta donde va a quedar la app:
		- *django-admin startproject magic_album .*
		- *python manage.py startapp cards*
  	- Se procede a copiar los archivos del proyecto descargados de este github en la carpeta donde quedará la app.
	- Crear BD en postgresql que se llame magic_album
	- Insertar los datos de conexión a la misma en la seccion databases en el archivo .env, el cual debes crear para el proyecto (en caso de ejecutar el proyecto local) o agregar las variables en el ambiente de producción.
	- Ejecutar el siguiente comando para crear las tablas en la BD:
		- *python manage.py migrate*
	- Ejecutar el siguiente comando para generar las llaves de encriptación, que van en el archivo .env:
		- Para SECRET_KEY: *python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"*
		- Para ENCRYPTION_KEY: *python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"*
	- Para crear los certificados https para la instalación local, debe ejecutar el programa mkcert, el cual puede descargar de https://github.com/FiloSottile/mkcert y ejecutar desde la linea de comandos los siguientes 2 comandos:
		- *mkcert -install* Este comando crea el certificado local
		- *mkcert localhost* Este comando genera el certificado y la llave.
	- Por último, ejecutar el servidor django con el comando, recuerde cambiar los nombres localhost+1.pem y localhost+1-key.pem por los nombres de los archivos generados en el paso anterior:
		*python manage.py runserver_plus --cert-file localhost+1.pem --key-file localhost+1-key.pem*


