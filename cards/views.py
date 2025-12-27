import json
import os
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse, HttpResponseForbidden
from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from .models import Card, WebAuthnCredential
from .encryption import EncryptedStorage
from fido2 import cbor 
from fido2.cose import CoseKey 
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.utils import websafe_decode, websafe_encode

# ==========================================
#  CONFIGURACIÓN DINÁMICA (CORRECCIÓN CRÍTICA)
# ==========================================
# Detectamos si estamos en Producción (Render) o Local
# Asegúrate de tener DEBUG = False en Render para que esto funcione bien
if settings.DEBUG:
    RP_ID = "localhost"
    RP_NAME = "Magic Album Local"
    EXPECTED_ORIGIN = "https://localhost:8000"
else:
    # TU DOMINIO REAL DE RENDER
    RP_ID = "webpasswordless.onrender.com"
    RP_NAME = "Magic Album"
    EXPECTED_ORIGIN = f"https://{RP_ID}"

rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
server = Fido2Server(rp)

User = get_user_model()

# ==========================================
#  VISTAS
# ==========================================

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'cards/login.html')

def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'cards/register.html')

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def dashboard(request):
    cards = Card.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'cards/dashboard.html', {'cards': cards})

@login_required
def upload_card(request):
    if request.method == 'POST':
        name = request.POST.get('card_name')
        f = request.FILES.get('image')
        if not f or f.content_type not in ['image/jpeg', 'image/png']:
            return HttpResponse("Formato inválido", status=400)
        card = Card(user=request.user)
        card.card_name = name 
        card.original_mime_type = f.content_type
        card.image = f 
        card.save()
        return redirect('dashboard')
    return render(request, 'cards/upload.html')

@login_required
def serve_image(request, card_id):
    card = get_object_or_404(Card, id=card_id)
    if card.user != request.user:
        return HttpResponseForbidden("No tienes permiso.")
    storage = EncryptedStorage()
    try:
        decrypted_content = storage.decrypt(card.image.name)
    except Exception as e:
        return HttpResponse("Error de descifrado", status=500)
    response = HttpResponse(decrypted_content, content_type=card.original_mime_type)
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@login_required
def delete_card(request, card_id):
    if request.method == 'POST':
        card = get_object_or_404(Card, id=card_id)
        if card.user != request.user:
            return HttpResponseForbidden("No tienes permiso.")
        try:
            if card.image: card.image.delete(save=False)
        except Exception: pass
        card.delete()
        return redirect('dashboard')
    return redirect('dashboard')


# ==========================================
#  API WEBAUTHN
# ==========================================

def webauthn_reg_options(request):
    if request.method != "POST": return JsonResponse({'error': 'POST required'}, status=405)
    try:
        data = json.loads(request.body)
        username = data.get("username")
        if User.objects.filter(username=username).exists():
            return JsonResponse({"status": "failed", "message": "El usuario ya existe"})

        user_entity = PublicKeyCredentialUserEntity(
            id=os.urandom(32),
            name=username,
            display_name=username,
        )
        options, state = server.register_begin(user_entity)
        request.session["state"] = state
        request.session["register_username"] = username
        return JsonResponse(dict(options))
    except Exception as e:
        return JsonResponse({"status": "failed", "message": str(e)})

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
            public_key=cbor.encode(credential_data.public_key), 
            sign_count=auth_data.counter, 
            name="Dispositivo Principal"
        )
        login(request, user)
        return JsonResponse({"status": "ok"})
    except Exception as e:
        return JsonResponse({"status": "failed", "message": str(e)})

def webauthn_auth_options(request):
    try:
        try:
            data = json.loads(request.body)
            username = data.get("username")
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return JsonResponse({"status": "failed", "message": "Usuario no encontrado"})

        credentials = WebAuthnCredential.objects.filter(user=user)
        if not credentials.exists():
            return JsonResponse({"status": "failed", "message": "Sin biometría"})
        
        allow_list = []
        for c in credentials:
            # CORRECCIÓN DE TIPOS (MemoryView -> Bytes)
            cid = bytes(c.credential_id) if isinstance(c.credential_id, memoryview) else c.credential_id
            if isinstance(cid, str): cid = cid.encode('utf-8')
            
            allow_list.append({"type": "public-key", "id": cid, "transports": []})

        options, state = server.authenticate_begin(allow_list)
        request.session["state"] = state
        request.session["login_username"] = username
        
        # Convertir a dict para evitar errores de atributos
        op_dict = dict(options)
        pk_data = op_dict['publicKey']
        
        response_data = {
            "publicKey": {
                "challenge": pk_data['challenge'], 
                "timeout": pk_data.get('timeout', 60000),
                "rpId": pk_data.get('rpId'),
                "userVerification": pk_data.get('userVerification'),
                "allowCredentials": [
                    {
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
        return JsonResponse({"status": "failed", "message": f"Error: {str(e)}"})

def webauthn_auth_verify(request):
    try:
        data = json.loads(request.body)
        state = request.session["state"]
        username = request.session["login_username"]
        user = User.objects.get(username=username)
        
        # 1. Recuperar credencial
        credential_id_bytes = websafe_decode(data['id'])
        stored_cred = WebAuthnCredential.objects.get(credential_id=credential_id_bytes)
        
        # === CORRECCIÓN "UNKNOWN CREDENTIAL ID" ===
        # PostgreSQL devuelve memoryview. FIDO2 exige bytes.
        # Forzamos la conversión en el objeto antes de pasarlo.
        if isinstance(stored_cred.credential_id, memoryview):
            stored_cred.credential_id = bytes(stored_cred.credential_id)
            
        # 2. Parchear Llave Pública
        pk_bytes = bytes(stored_cred.public_key)
        pk_dict = cbor.decode(pk_bytes)
        stored_cred.public_key = CoseKey.parse(pk_dict)
        
        # 3. Verificar
        server.authenticate_complete(
            state,
            [stored_cred], # La librería buscará stored_cred.credential_id aquí
            data
        )
        
        login(request, user)
        return JsonResponse({"status": "ok"})
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"status": "failed", "message": str(e)})

    #NEl

