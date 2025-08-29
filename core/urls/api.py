from django.urls import path
from ..views import api

urlpatterns = [
    path('me/', api.me, name='me'),
    path('lists/', api.lists, name='lists'),
    path('lists/<uuid:list_id>/', api.list_detail, name='list_detail'),
    path('todos/', api.todos, name='todos'),
    path('todos/<uuid:todo_id>/', api.todo_detail, name='todo_detail'),
    path('todos/<uuid:todo_id>/toggle/', api.todo_toggle, name='todo_toggle'),
    path('todos/bulk/', api.todos_bulk, name='todos_bulk'),
]