from django.urls import path, include

urlpatterns = [
    path('auth/', include('core.urls.auth')),
    path('', include('core.urls.api')),
]