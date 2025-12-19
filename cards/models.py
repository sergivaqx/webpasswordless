from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from cryptography.fernet import Fernet
from .encryption import EncryptedStorage

# Instancia del storage cifrado
encrypted_storage = EncryptedStorage()

class User(AbstractUser):
    # WebAuthn no necesita password, pero Django lo requiere por defecto.
    # Lo haremos "unusable" al registrar.
    pass

class WebAuthnCredential(models.Model):
    """Almacena las llaves públicas (Passkeys) de los usuarios"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='credentials')
    credential_id = models.BinaryField(unique=True) # ID binario del autenticador
    public_key = models.BinaryField()               # Llave pública COSE
    sign_count = models.IntegerField(default=0)     # Para evitar ataques de clonación
    name = models.CharField(max_length=255, blank=True) # Ej: "iPhone de Juan"

class Card(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    # Campo Cifrado en BD (Texto)
    _card_name = models.TextField(db_column='card_name') 
    
    # Archivo Cifrado en Disco
    image = models.FileField(storage=encrypted_storage, upload_to='cards/')
    original_mime_type = models.CharField(max_length=50) # Ej: image/jpeg
    created_at = models.DateTimeField(auto_now_add=True)

    # Getter/Setter para cifrar/descifrar el nombre automáticamente
    @property
    def card_name(self):
        f = Fernet(settings.ENCRYPTION_KEY)
        return f.decrypt(self._card_name.encode()).decode()

    @card_name.setter
    def card_name(self, value):
        f = Fernet(settings.ENCRYPTION_KEY)
        self._card_name = f.encrypt(value.encode()).decode()

    def save(self, *args, **kwargs):
        # Aseguramos que el nombre esté cifrado antes de guardar si se asignó directo
        if not self._card_name.startswith('gAAAA'): # Chequeo simple de Fernet
             self.card_name = self._card_name
        super().save(*args, **kwargs)