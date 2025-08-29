from django.urls import path
from . import views

urlpatterns = [
    # Auth
    path('auth/csrf/', views.csrf_token, name='csrf'),
    path('auth/login/', views.login, name='login'),
    path('auth/logout/', views.logout, name='logout'),
    
    # API
    path('me/', views.me, name='me'),
    path('lists/', views.lists, name='lists'),
    path('lists/<uuid:list_id>/', views.list_detail, name='list_detail'),
    path('todos/', views.todos, name='todos'),
    path('todos/<uuid:todo_id>/', views.todo_detail, name='todo_detail'),
    path('todos/<uuid:todo_id>/toggle/', views.todo_toggle, name='todo_toggle'),
    path('todos/bulk/', views.todos_bulk, name='todos_bulk'),
]