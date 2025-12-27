import os
from cryptography.fernet import Fernet
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# 1. Definición de rutas base
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# 2. Seguridad
# ¡ADVERTENCIA! Mantén esta llave secreta en producción.
SECRET_KEY = os.getenv('SECRET_KEY')

# Ponlo en True para desarrollar, False para producción
DEBUG = False 

ALLOWED_HOSTS = ['webpasswordless.onrender.com']

# 3. Aplicaciones Instaladas
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Librerías de terceros (si las instalaste)
    'django_extensions', 

    # TUS APLICACIONES
    'cards', 
]

# 4. Middleware (Procesadores de peticiones)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
]

# 5. ¡AQUÍ ESTABA TU ERROR!
# Esto le dice a Django dónde buscar las rutas principales
ROOT_URLCONF = 'magic_album.urls'

# 6. Configuración de Plantillas (HTML)
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'], # Carpeta global de templates (opcional)
        'APP_DIRS': True, # Busca templates dentro de la carpeta de cada app ('cards/templates')
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'magic_album.wsgi.application'

# 7. Base de Datos (PostgreSQL)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT'),
    }
}

# 8. Validadores de contraseñas (Aunque usemos WebAuthn, Django los requiere por defecto)
AUTH_PASSWORD_VALIDATORS = [
    { 'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator', },
    { 'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', },
    { 'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator', },
    { 'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator', },
]

# 9. Internacionalización
LANGUAGE_CODE = 'es-es'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# 10. Archivos Estáticos (CSS, JS, Images del sistema)
STATIC_URL = 'static/'

# 11. Archivos Subidos por el Usuario (NUESTRO SISTEMA CIFRADO)
# Definimos la carpeta donde se guardarán los .enc
MEDIA_ROOT = BASE_DIR / 'encrypted_storage'
# No definimos MEDIA_URL porque no queremos que sean accesibles vía web directa

# 12. Configuración del Modelo de Usuario
# Usamos el modelo por defecto de Django, pero si creaste uno propio:
AUTH_USER_MODEL = 'cards.User' 

# 13. Llave Maestra de Cifrado (AES-256 Fernet)
# Si no existe la variable de entorno, usa una por defecto (SOLO DEV)
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')

# 14. Tipo de campo para Auto-incremento

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

