from django.urls import path
from ..swagger_views import (
    me, lists, list_detail, todos, todo_detail, 
    todo_toggle, todos_bulk
)

urlpatterns = [
    path('me/', me, name='me'),
    path('lists/', lists, name='lists'),
    path('lists/<uuid:list_id>/', list_detail, name='list_detail'),
    path('todos/', todos, name='todos'),
    path('todos/<uuid:todo_id>/', todo_detail, name='todo_detail'),
    path('todos/<uuid:todo_id>/toggle/', todo_toggle, name='todo_toggle'),
    path('todos/bulk/', todos_bulk, name='todos_bulk'),
]