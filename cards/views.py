import json
import os
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse, HttpResponseForbidden
from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt # Solo si es necesario, mejor usar token
from django.conf import settings
from .models import Card, WebAuthnCredential
from .encryption import EncryptedStorage
from fido2 import cbor # <--- IMPORTANTE: Para convertir Obj -> Bytes
from fido2.cose import CoseKey # <--- IMPORTANTE: Para convertir Bytes -> Obj

# --- Dependencias FIDO2 (WebAuthn) ---
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.utils import websafe_decode, websafe_encode

# Configuración del Servidor FIDO2
# Si DEBUG es True, estamos en local. Si es False, estamos en Render/Producción.
if settings.DEBUG:
    RP_ID = "localhost"
    EXPECTED_ORIGIN = "https://localhost:8000"
else:
    # Tu dominio real en Render
    RP_ID = "webpasswordless.onrender.com"
    EXPECTED_ORIGIN = f"https://{RP_ID}"
    
rp = PublicKeyCredentialRpEntity(id=RP_ID, name="Magic Album")
server = Fido2Server(rp)

User = get_user_model()

# ==========================================
#  VISTAS DE NAVEGACIÓN (HTML)
# ==========================================

def login_view(request):
    """Renderiza la página de login"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'cards/login.html')

def register_view(request):
    """Renderiza la página de registro"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'cards/register.html')

def logout_view(request):
    """Cierra sesión y limpia cookies"""
    logout(request)
    return redirect('login')

@login_required
def dashboard(request):
    """Muestra el álbum. El descifrado de nombres ocurre en el template."""
    cards = Card.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'cards/dashboard.html', {'cards': cards})

@login_required
def upload_card(request):
    """Maneja la subida cifrada de cartas"""
    if request.method == 'POST':
        name = request.POST.get('card_name')
        f = request.FILES.get('image')
        
        # Validaciones básicas
        if not f or f.content_type not in ['image/jpeg', 'image/png']:
            return HttpResponse("Formato inválido o archivo faltante", status=400)
            
        card = Card(user=request.user)
        card.card_name = name # El setter del modelo cifra esto automáticamente
        card.original_mime_type = f.content_type
        card.image = f # El Storage personalizado cifra esto automáticamente
        card.save()
        
        return redirect('dashboard')
    
    return render(request, 'cards/upload.html')

@login_required
def serve_image(request, card_id):
    """
    Descifra la imagen 'al vuelo' y la entrega al navegador.
    NUNCA guarda la imagen descifrada en disco.
    """
    card = get_object_or_404(Card, id=card_id)
    
    # Seguridad IDOR: Solo el dueño puede verla
    if card.user != request.user:
        return HttpResponseForbidden("No tienes permiso para ver esta carta.")
    
    # Descifrar usando nuestro Storage personalizado
    storage = EncryptedStorage()
    try:
        # storage.decrypt es el método manual que creamos en encryption.py
        decrypted_content = storage.decrypt(card.image.name)
    except Exception as e:
        print(f"Error descifrando: {e}")
        return HttpResponse("Error de descifrado", status=500)
        
    response = HttpResponse(decrypted_content, content_type=card.original_mime_type)
    # Evitar caché en el navegador para máxima seguridad
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@login_required
def delete_card(request, card_id):
    """Permite al usuario borrar una de sus cartas"""
    if request.method == 'POST':
        card = get_object_or_404(Card, id=card_id)
        
        # Seguridad: Verificar que la carta pertenezca al usuario logueado
        if card.user != request.user:
            return HttpResponseForbidden("No tienes permiso para borrar esta carta.")
        
        # 1. Borrar el archivo físico (opcional, pero recomendado para no llenar el disco)
        # Nota: Django a veces no borra archivos automáticamente al borrar el registro
        try:
            if card.image:
                card.image.delete(save=False)
        except Exception as e:
            print(f"Error borrando archivo: {e}")

        # 2. Borrar el registro de la base de datos
        card.delete()
        
        return redirect('dashboard')
    
    # Si intentan entrar por GET (escribiendo la url), los mandamos al dashboard
    return redirect('dashboard')


# ==========================================
#  API WEBAUTHN (AJAX/FETCH)
# ==========================================

# 1. REGISTRO: Opciones (Challenge)
def webauthn_reg_options(request):
    if request.method != "POST": return JsonResponse({'error': 'POST required'}, status=405)
    
    data = json.loads(request.body)
    username = data.get("username")
    
    if User.objects.filter(username=username).exists():
        return JsonResponse({"status": "failed", "message": "El usuario ya existe"})

    # Generar desafío
    user_entity = PublicKeyCredentialUserEntity(
        id=os.urandom(32),
        name=username,
        display_name=username,
    )
    options, state = server.register_begin(user_entity)
    
    # Guardar estado en sesión para verificar después
    request.session["state"] = state
    request.session["register_username"] = username
    
    return JsonResponse(dict(options))

# 2. REGISTRO: Verificación
def webauthn_reg_verify(request):
    try:
        data = json.loads(request.body)
        state = request.session["state"]
        username = request.session["register_username"]
        
        auth_data = server.register_complete(state, data)
        credential_data = auth_data.credential_data
        
        user = User.objects.create(username=username)
        user.set_unusable_password() 
        user.save()

        WebAuthnCredential.objects.create(
            user=user,
            credential_id=credential_data.credential_id,
            
            # --- CORRECCIÓN AQUÍ ---
            # Convertimos el Objeto ES256 a Bytes usando CBOR
            public_key=cbor.encode(credential_data.public_key), 
            # -----------------------

            sign_count=auth_data.counter, 
            name="Dispositivo Principal"
        )
        
        login(request, user)
        return JsonResponse({"status": "ok"})
        
    except Exception as e:
        print(f"Error registro: {e}")
        return JsonResponse({"status": "failed", "message": str(e)})


# 3. LOGIN: Opciones (Challenge)
# cards/views.py

def webauthn_auth_options(request):
    try:
        # 1. Validaciones básicas
        try:
            data = json.loads(request.body)
            username = data.get("username")
            if not username:
                return JsonResponse({"status": "failed", "message": "Falta el usuario"})
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return JsonResponse({"status": "failed", "message": "Usuario no encontrado"})
        except json.JSONDecodeError:
            return JsonResponse({"status": "failed", "message": "JSON inválido"})

        # 2. Buscar credenciales
        credentials = WebAuthnCredential.objects.filter(user=user)
        if not credentials.exists():
            return JsonResponse({"status": "failed", "message": "Sin biometría"})
        
        # 3. Preparar lista para FIDO2
        allow_list = []
        for c in credentials:
            cid = c.credential_id
            if isinstance(cid, str): cid = cid.encode('utf-8') 
            elif isinstance(cid, memoryview): cid = bytes(cid)
            allow_list.append({"type": "public-key", "id": cid, "transports": []})

        # 4. Generar opciones
        options, state = server.authenticate_begin(allow_list)
        request.session["state"] = state
        request.session["login_username"] = username
        
        # === CORRECCIÓN BASADA EN TU DIAGNÓSTICO ===
        
        # Paso A: Convertir a diccionario
        # Esto nos da: {'publicKey': {'challenge': '...', ...}}
        full_dict = dict(options)
        
        # Paso B: Extraer la "caja" interna
        pk_data = full_dict['publicKey']
        
        # Paso C: Construir respuesta
        # Nota: Tu log mostró que 'challenge' e 'id' YA SON STRINGS en esta versión.
        # No hace falta usar websafe_encode de nuevo, o se rompería.
        
        response_data = {
            "publicKey": {
                "challenge": pk_data['challenge'], 
                "timeout": pk_data.get('timeout', 60000),
                "rpId": pk_data.get('rpId'),
                "userVerification": pk_data.get('userVerification'),
                "allowCredentials": [
                    {
                        # Tu log mostró que 'type' es un Enum (<PublicKeyCredentialType...>)
                        # Debemos sacar su .value ('public-key') para que sea JSON válido
                        "type": cred['type'].value if hasattr(cred['type'], 'value') else str(cred['type']),
                        "id": cred['id'],
                        "transports": cred.get('transports', [])
                    }
                    for cred in pk_data['allowCredentials']
                ]
            }
        }
        return JsonResponse(response_data)

    except Exception as e:
        import traceback
        print("============== ERROR EN LOGIN ==============")
        traceback.print_exc()
        return JsonResponse({"status": "failed", "message": f"Error interno: {str(e)}"})

# 4. LOGIN: Verificación
# cards/views.py

def webauthn_auth_verify(request):
    try:
        data = json.loads(request.body)
        state = request.session["state"]
        username = request.session["login_username"]
        user = User.objects.get(username=username)
        
        # 1. Recuperar credencial de la BD
        credential_id_bytes = websafe_decode(data['id'])
        stored_cred = WebAuthnCredential.objects.get(credential_id=credential_id_bytes)
        
        # 2. PARCHEAR: Convertir Bytes -> Diccionario -> Objeto CoseKey
        # (Esto arregla el error "AttributeError: 'bytes' object has no attribute 'get'")
        pk_bytes = bytes(stored_cred.public_key)
        pk_dict = cbor.decode(pk_bytes)
        stored_cred.public_key = CoseKey.parse(pk_dict)
        
        # 3. Verificar firma
        # (Esto arregla el error "TypeError: takes 4 positional arguments but 5 were given")
        server.authenticate_complete(
            state,
            [stored_cred],
            data  # <--- SOLO enviamos 'data'. Eliminamos data['id'] que sobraba.
        )
        
        # 4. Login exitoso
        login(request, user)
        return JsonResponse({"status": "ok"})
        
    except Exception as e:
        import traceback
        print("============== ERROR EN VERIFY LOGIN ==============")
        traceback.print_exc()
        return JsonResponse({"status": "failed", "message": str(e)})
    

    #NEl
