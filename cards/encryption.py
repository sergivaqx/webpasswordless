from django.core.files.storage import FileSystemStorage
from django.core.files.base import ContentFile
from django.conf import settings
from cryptography.fernet import Fernet
import os

class EncryptedStorage(FileSystemStorage):
    """
    Sistema de almacenamiento que cifra al guardar y NO descifra automáticamente al abrir
    (para obligar a usar una vista segura de decodificación).
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cipher = Fernet(settings.ENCRYPTION_KEY)

    def _save(self, name, content):
        # 1. Leer contenido original
        data = content.read()
        
        # 2. Cifrar contenido (AES)
        encrypted_data = self.cipher.encrypt(data)
        
        # 3. Guardar el blob cifrado con una extensión segura
        # Se cambia la extensión para que el servidor web no intente mostrarlo
        clean_name = os.path.splitext(name)[0] + ".enc"
        
        return super()._save(clean_name, ContentFile(encrypted_data))

    def decrypt(self, name):
        """Método manual para recuperar el archivo real"""
        path = self.path(name)
        with open(path, 'rb') as f:
            encrypted_data = f.read()
        return self.cipher.decrypt(encrypted_data)