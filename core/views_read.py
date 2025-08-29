"""Read-only API endpoints for better security separation"""
import logging
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.core.cache import cache
from drf_spectacular.utils import extend_schema
from .models import List, Todo
from .views import get_user_from_cache, get_ip, paginate

logger = logging.getLogger(__name__)

@extend_schema(summary="Get Lists", tags=["Lists"])
@require_http_methods(["GET"])
def lists_read(request):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    # Try cache first
    cache_key = f'user_lists:{user.id}'
    q = request.GET.get('q', '').strip()
    if q:
        cache_key += f':search:{q}'
    
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)
    
    qs = List.objects.filter(user=user).select_related('user').order_by('-created_at')
    if q:
        qs = qs.filter(name__icontains=q)
    
    items, cursor = paginate(qs, request)
    data = {
        'data': [{'id': str(l.id), 'name': l.name, 'color': l.color, 'created_at': l.created_at.isoformat()} for l in items],
        'next_cursor': cursor
    }
    
    # Cache for 5 minutes
    cache.set(cache_key, data, timeout=300)
    return JsonResponse(data)

@extend_schema(summary="Get List Detail", tags=["Lists"])
@require_http_methods(["GET"])
def list_detail_read(request, list_id):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    cache_key = f'list_detail:{list_id}:{user.id}'
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)
    
    try:
        list_obj = List.objects.select_related('user').get(id=list_id, user=user)
        data = {
            'id': str(list_obj.id), 
            'name': list_obj.name, 
            'color': list_obj.color,
            'created_at': list_obj.created_at.isoformat(),
            'updated_at': list_obj.updated_at.isoformat()
        }
        cache.set(cache_key, data, timeout=300)
        return JsonResponse(data)
    except List.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)

@extend_schema(summary="Get Todos", tags=["Todos"])
@require_http_methods(["GET"])
def todos_read(request):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    # Build cache key based on filters
    filters = {
        'list_id': request.GET.get('list_id'),
        'status': request.GET.get('status'),
        'q': request.GET.get('q', '').strip()
    }
    cache_key = f'user_todos:{user.id}:' + ':'.join(f'{k}={v}' for k, v in filters.items() if v)
    
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)
    
    qs = Todo.objects.filter(list__user=user).select_related('list').order_by('-updated_at')
    
    # Apply filters
    if filters['list_id']:
        qs = qs.filter(list_id=filters['list_id'])
    if filters['status']:
        qs = qs.filter(status=filters['status'])
    if filters['q']:
        qs = qs.filter(title__icontains=filters['q'])
    
    items, cursor = paginate(qs, request)
    data = {
        'data': [{
            'id': str(t.id), 
            'list_id': str(t.list_id), 
            'title': t.title,
            'note': t.note,
            'status': t.status, 
            'priority': t.priority, 
            'due_date': t.due_date.isoformat() if t.due_date else None,
            'version': t.version,
            'updated_at': t.updated_at.isoformat()
        } for t in items],
        'next_cursor': cursor
    }
    
    # Cache for 2 minutes (shorter due to frequent updates)
    cache.set(cache_key, data, timeout=120)
    return JsonResponse(data)

@extend_schema(summary="Get Todo Detail", tags=["Todos"])
@require_http_methods(["GET"])
def todo_detail_read(request, todo_id):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    cache_key = f'todo_detail:{todo_id}:{user.id}'
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)
    
    try:
        todo = Todo.objects.select_related('list').get(id=todo_id, list__user=user)
        data = {
            'id': str(todo.id), 
            'list_id': str(todo.list_id),
            'title': todo.title, 
            'note': todo.note,
            'status': todo.status,
            'priority': todo.priority, 
            'due_date': todo.due_date.isoformat() if todo.due_date else None,
            'version': todo.version,
            'updated_at': todo.updated_at.isoformat()
        }
        cache.set(cache_key, data, timeout=300)
        return JsonResponse(data)
    except Todo.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)