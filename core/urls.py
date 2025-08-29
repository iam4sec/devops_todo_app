from django.urls import path
from . import views

urlpatterns = [
    # Auth
    path('auth/csrf/', views.csrf_token, name='csrf'),
    path('auth/login/', views.login, name='login'),
    path('auth/logout/', views.logout, name='logout'),
    
    # User
    path('me/', views.me, name='me'),
    
    # Lists
    path('lists/', views.lists, name='lists'),
    path('lists/create/', views.lists_create, name='lists_create'),
    path('lists/<uuid:list_id>/', views.list_detail, name='list_detail'),
    path('lists/<uuid:list_id>/update/', views.list_update, name='list_update'),
    path('lists/<uuid:list_id>/delete/', views.list_delete, name='list_delete'),
    
    # Todos
    path('todos/', views.todos, name='todos'),
    path('todos/create/', views.todos_create, name='todos_create'),
    path('todos/<uuid:todo_id>/', views.todo_detail, name='todo_detail'),
    path('todos/<uuid:todo_id>/update/', views.todo_update, name='todo_update'),
    path('todos/<uuid:todo_id>/delete/', views.todo_delete, name='todo_delete'),
    path('todos/<uuid:todo_id>/toggle/', views.todo_toggle, name='todo_toggle'),
    path('todos/bulk/', views.todos_bulk, name='todos_bulk'),
]