from django.urls import path
from . import views

urlpatterns = [
    # --- Vistas Visuales (HTML) ---
    path('', views.login_view, name='login'),             # Pantalla de Login
    path('register/', views.register_view, name='register'), # Pantalla de Registro
    path('dashboard/', views.dashboard, name='dashboard'),   # El álbum seguro
    path('upload/', views.upload_card, name='upload'),       # Formulario de subida
    path('logout/', views.logout_view, name='logout'),

    # --- Vista Crítica de Seguridad ---
    # Esta ruta sirve la imagen descifrada en memoria
    path('secure-image/<int:card_id>/', views.serve_image, name='card_image'),
    path('delete_card/<int:card_id>/', views.delete_card, name='delete_card'),

    # --- Endpoints API para WebAuthn (AJAX/Fetch) ---
    # Estos son llamados por el JavaScript del login.html
    path('api/auth/options/', views.webauthn_auth_options, name='auth_options'),
    path('api/auth/verify/', views.webauthn_auth_verify, name='auth_verify'),
    path('api/register/options/', views.webauthn_reg_options, name='reg_options'),
    path('api/register/verify/', views.webauthn_reg_verify, name='reg_verify'),
]