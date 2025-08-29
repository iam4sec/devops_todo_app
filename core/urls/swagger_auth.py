from django.urls import path
from ..swagger_views import csrf_token, login, refresh, logout

urlpatterns = [
    path('csrf/', csrf_token, name='csrf'),
    path('login/', login, name='login'),
    path('refresh/', refresh, name='refresh'),
    path('logout/', logout, name='logout'),
]