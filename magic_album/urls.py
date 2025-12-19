from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    # Ruta al panel de administración de Django (opcional, pero útil)
    path('admin/', admin.site.urls),
    
    # Delegamos todo el tráfico raíz a la aplicación 'cards'
    path('', include('cards.urls')),
]