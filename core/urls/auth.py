from django.urls import path
from ..views import auth

urlpatterns = [
    path('csrf/', auth.csrf_token, name='csrf'),
    path('login/', auth.login, name='login'),
    path('refresh/', auth.refresh, name='refresh'),
    path('logout/', auth.logout, name='logout'),
]