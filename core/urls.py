from django.urls import path
from . import views

from django.views.decorators.http import require_http_methods
from django.http import HttpResponseNotAllowed

# Combined view handlers for cleaner URLs
@require_http_methods(["GET", "POST"])
def lists_handler(request):
    if request.method == 'GET':
        return views.lists(request)
    elif request.method == 'POST':
        return views.lists_create(request)
    return HttpResponseNotAllowed(['GET', 'POST'])

@require_http_methods(["GET", "PATCH", "DELETE"])
def list_detail_handler(request, list_id):
    if request.method == 'GET':
        return views.list_detail(request, list_id)
    elif request.method == 'PATCH':
        return views.list_update(request, list_id)
    elif request.method == 'DELETE':
        return views.list_delete(request, list_id)
    return HttpResponseNotAllowed(['GET', 'PATCH', 'DELETE'])

@require_http_methods(["GET", "POST"])
def todos_handler(request):
    if request.method == 'GET':
        return views.todos(request)
    elif request.method == 'POST':
        return views.todos_create(request)
    return HttpResponseNotAllowed(['GET', 'POST'])

@require_http_methods(["GET", "PATCH", "DELETE"])
def todo_detail_handler(request, todo_id):
    if request.method == 'GET':
        return views.todo_detail(request, todo_id)
    elif request.method == 'PATCH':
        return views.todo_update(request, todo_id)
    elif request.method == 'DELETE':
        return views.todo_delete(request, todo_id)
    return HttpResponseNotAllowed(['GET', 'PATCH', 'DELETE'])

urlpatterns = [
    # Root
    path('', views.api_info, name='api_info'),
    
    # Auth
    path('auth/csrf/', views.csrf_token, name='csrf'),
    path('auth/login/', views.login, name='login'),
    path('auth/refresh/', views.refresh, name='refresh'),
    path('auth/logout/', views.logout, name='logout'),
    
    # User
    path('me/', views.me, name='me'),
    
    # Lists - Combined endpoints
    path('lists/', lists_handler, name='lists'),
    path('lists/<uuid:list_id>/', list_detail_handler, name='list_detail'),
    
    # Todos - Combined endpoints
    path('todos/', todos_handler, name='todos'),
    path('todos/<uuid:todo_id>/', todo_detail_handler, name='todo_detail'),
    path('todos/<uuid:todo_id>/toggle/', views.todo_toggle, name='todo_toggle'),
    path('todos/bulk/', views.todos_bulk, name='todos_bulk'),
]