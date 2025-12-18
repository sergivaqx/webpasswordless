1. Estructura
	Framework: Django 5.0+
	BD: PostgreSQL
	Librerías Clave:
		cryptography: Para cifrado AES (Fernet).
		fido2: Para manejar el protocolo WebAuthn (Passkeys).
		psycopg: Driver de PostgreSQL.

2. Instalación
	- Instalar las librerias usando pip install:
		- django 
		- psycopg[binary] 
		- cryptography 
		- fido2 
		- django-extensions 
		- python-dotenv
	- Ejecutar los siguientes comandos en la consola, dentro de la carpeta donde va a quedar la app:
		- django-admin startproject magic_album .
		- python manage.py startapp cards
	- Crear BD en postgresql que se llame magic_album
	- Insertar los datos de conexión a la misma en la seccion databases en el archivo settings.py, que se encuentra en la carpeta magic_album
	- Ejecutar el siguiente comando para crear las tablas en la BD:
		- python manage.py migrate
	- Ejecutar el siguiente comando para generar las llaves de encriptación, que van en el archivo .env:
		Para SECRET_KEY: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
		Para ENCRYPTION_KEY: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
	- Insertar la llave generada en el archivo settings.py, en la variable ENCRYPTION_KEY, en el espacio donde dice inserte llave aquí
	- Por último, ejecutar el servidor django con el comando:
		python manage.py runserver
