from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from django.conf import settings

# Configuración del Servidor FIDO2
rp = PublicKeyCredentialRpEntity("magic-album.local", "Magic Album")
server = Fido2Server(rp)

# Estas funciones se usarían en tus vistas para:
# 1. Generar opciones de registro (challenge)
# 2. Verificar la respuesta del navegador
# 3. Guardar la credencial en el modelo WebAuthnCredential