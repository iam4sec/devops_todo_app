import json
import logging
from datetime import timedelta
from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from django.middleware.csrf import get_token
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from django.core.exceptions import ValidationError
from drf_spectacular.utils import extend_schema
from .models import User, Session, List, Todo
from .serializers import LoginSerializer, ListSerializer, TodoSerializer

logger = logging.getLogger(__name__)

# Utilities
def get_ip(request):
    return request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0] or request.META.get('REMOTE_ADDR')

def get_user_from_cache(request):
    """Get user from cache with optimized session lookup"""
    sid = request.COOKIES.get('sid')
    if not sid:
        return None
    
    # Try cache first
    cache_key = f'session:{sid}'
    cached_session = cache.get(cache_key)
    
    if cached_session:
        if cached_session['expires_at'] > timezone.now() and cached_session['ip'] == get_ip(request):
            try:
                return User.objects.get(id=cached_session['user_id'])
            except User.DoesNotExist:
                cache.delete(cache_key)
                return None
        else:
            cache.delete(cache_key)
    
    # Fallback to database
    try:
        session = Session.objects.select_related('user').get(
            id=sid, expires_at__gt=timezone.now()
        )
        if session.ip != get_ip(request):
            session.delete()
            return None
        
        # Cache for future requests
        cache.set(cache_key, {
            'user_id': session.user.id,
            'expires_at': session.expires_at,
            'ip': session.ip
        }, timeout=300)
        
        return session.user
    except (Session.DoesNotExist, ValidationError) as e:
        logger.warning(f"Session validation failed: {e}")
        return None

# Replaced with get_user_from_cache above

def paginate(queryset, request, limit=50):
    """Optimized pagination with proper error handling"""
    cursor = request.GET.get('cursor')
    if cursor:
        try:
            cursor_data = json.loads(cursor)
            cursor_id = cursor_data.get('id')
            if cursor_id:
                queryset = queryset.filter(id__gt=cursor_id)
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Invalid cursor format: {e}")
    
    items = list(queryset[:limit + 1])  # Fetch one extra to check if more exist
    has_more = len(items) > limit
    if has_more:
        items = items[:limit]
    
    next_cursor = json.dumps({'id': str(items[-1].id)}) if has_more and items else None
    return items, next_cursor

# Auth Views
@extend_schema(summary="Get CSRF Token", tags=["Auth"])
@ensure_csrf_cookie
@require_http_methods(["GET"])
def csrf_token(request):
    return JsonResponse({'csrfToken': get_token(request)})

@extend_schema(summary="Login", tags=["Auth"])
@csrf_protect
@require_http_methods(["POST"])
def login(request):
    try:
        data = json.loads(request.body)
        serializer = LoginSerializer(data)
        validated_data = serializer.validate()
        
        if not validated_data:
            return JsonResponse({'errors': serializer.errors}, status=400)
        
        user = validated_data['user']
        ip = get_ip(request)
        
        # Clean up old sessions for this user
        Session.objects.filter(user=user, expires_at__lt=timezone.now()).delete()
        
        session = Session.objects.create(
            user=user, ip=ip,
            expires_at=timezone.now() + timedelta(seconds=settings.SESSION_COOKIE_AGE)
        )
        
        # Cache session data
        cache.set(f'session:{session.id}', {
            'user_id': user.id,
            'expires_at': session.expires_at,
            'ip': ip
        }, timeout=settings.SESSION_COOKIE_AGE)
        
        response = JsonResponse({'user_id': str(user.id)})
        response.set_cookie(
            'sid', str(session.id), 
            max_age=settings.SESSION_COOKIE_AGE,
            httponly=True, 
            secure=not settings.DEBUG,
            samesite='Lax'
        )
        
        logger.info(f"User {user.email} logged in from {ip}")
        return response
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Login error: {e}")
        return JsonResponse({'error': 'Login failed'}, status=500)

@extend_schema(summary="Logout", tags=["Auth"])
@csrf_protect
@require_http_methods(["POST"])
def logout(request):
    sid = request.COOKIES.get('sid')
    if sid:
        Session.objects.filter(id=sid).delete()
        cache.delete(f'session:{sid}')
        logger.info(f"User logged out, session {sid} deleted")
    
    response = JsonResponse({'logged_out': True})
    response.delete_cookie('sid')
    return response

# API Views
@extend_schema(summary="Current User", tags=["User"])
@require_http_methods(["GET"])
def me(request):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    return JsonResponse({'id': str(user.id), 'email': user.email})

@extend_schema(summary="Lists", tags=["Lists"])
@require_http_methods(["GET"])
def lists(request):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
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
        'data': [{'id': str(l.id), 'name': l.name, 'color': l.color} for l in items],
        'next_cursor': cursor
    }
    
    cache.set(cache_key, data, timeout=300)
    return JsonResponse(data)

@extend_schema(summary="Create List", tags=["Lists"])
@csrf_protect
@require_http_methods(["POST"])
def lists_create(request):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    try:
        data = json.loads(request.body)
        serializer = ListSerializer(data)
        validated_data = serializer.validate()
        
        if not validated_data:
            return JsonResponse({'errors': serializer.errors}, status=400)
        
        with transaction.atomic():
            list_obj = List.objects.create(user=user, **validated_data)
            cache.delete_many([f'user_lists:{user.id}*'])
            
        return JsonResponse({
            'id': str(list_obj.id), 'name': list_obj.name, 'color': list_obj.color
        }, status=201)
    except Exception as e:
        logger.error(f"List creation error: {e}")
        return JsonResponse({'error': 'Creation failed'}, status=500)

@extend_schema(summary="List Detail", tags=["Lists"])
@require_http_methods(["GET"])
def list_detail(request, list_id):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    cache_key = f'list_detail:{list_id}:{user.id}'
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)
    
    try:
        list_obj = List.objects.get(id=list_id, user=user)
        data = {'id': str(list_obj.id), 'name': list_obj.name, 'color': list_obj.color}
        cache.set(cache_key, data, timeout=300)
        return JsonResponse(data)
    except List.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)

@extend_schema(summary="Update List", tags=["Lists"])
@csrf_protect
@require_http_methods(["PATCH"])
def list_update(request, list_id):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    try:
        list_obj = List.objects.select_for_update().get(id=list_id, user=user)
        data = json.loads(request.body)
        serializer = ListSerializer(data)
        validated_data = serializer.validate()
        
        if not validated_data:
            return JsonResponse({'errors': serializer.errors}, status=400)
        
        with transaction.atomic():
            for k, v in validated_data.items():
                if v is not None:
                    setattr(list_obj, k, v)
            list_obj.save()
            cache.delete_many([f'user_lists:{user.id}*', f'list_detail:{list_id}:{user.id}'])
            
        return JsonResponse({'id': str(list_obj.id), 'name': list_obj.name, 'color': list_obj.color})
    except List.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    except Exception as e:
        logger.error(f"List update error: {e}")
        return JsonResponse({'error': 'Update failed'}, status=500)

@extend_schema(summary="Delete List", tags=["Lists"])
@csrf_protect
@require_http_methods(["DELETE"])
def list_delete(request, list_id):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    try:
        with transaction.atomic():
            list_obj = List.objects.select_for_update().get(id=list_id, user=user)
            list_obj.delete()
            cache.delete_many([f'user_lists:{user.id}*', f'list_detail:{list_id}:{user.id}'])
        return JsonResponse({}, status=204)
    except List.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)

@extend_schema(summary="Todos", tags=["Todos"])
@require_http_methods(["GET"])
def todos(request):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
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
    if filters['list_id']:
        qs = qs.filter(list_id=filters['list_id'])
    if filters['status']:
        qs = qs.filter(status=filters['status'])
    if filters['q']:
        qs = qs.filter(title__icontains=filters['q'])
    
    items, cursor = paginate(qs, request)
    data = {
        'data': [{
            'id': str(t.id), 'list_id': str(t.list_id), 'title': t.title,
            'status': t.status, 'priority': t.priority, 'version': t.version
        } for t in items],
        'next_cursor': cursor
    }
    
    cache.set(cache_key, data, timeout=120)
    return JsonResponse(data)

@extend_schema(summary="Create Todo", tags=["Todos"])
@csrf_protect
@require_http_methods(["POST"])
def todos_create(request):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    try:
        data = json.loads(request.body)
        serializer = TodoSerializer(data)
        validated_data = serializer.validate()
        
        if not validated_data:
            return JsonResponse({'errors': serializer.errors}, status=400)
        
        list_obj = List.objects.get(id=validated_data['list_id'], user=user)
        with transaction.atomic():
            todo_data = {k: v for k, v in validated_data.items() if k != 'list_id'}
            todo = Todo.objects.create(list=list_obj, **todo_data)
            cache.delete_many([f'user_todos:{user.id}*'])
            
        return JsonResponse({
            'id': str(todo.id), 'title': todo.title, 'status': todo.status
        }, status=201)
    except List.DoesNotExist:
        return JsonResponse({'error': 'List not found'}, status=404)
    except Exception as e:
        logger.error(f"Todo creation error: {e}")
        return JsonResponse({'error': 'Creation failed'}, status=500)

@extend_schema(summary="Todo Detail", tags=["Todos"])
@require_http_methods(["GET"])
def todo_detail(request, todo_id):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    cache_key = f'todo_detail:{todo_id}:{user.id}'
    cached_data = cache.get(cache_key)
    if cached_data:
        return JsonResponse(cached_data)
    
    try:
        todo = Todo.objects.get(id=todo_id, list__user=user)
        data = {
            'id': str(todo.id), 'title': todo.title, 'status': todo.status,
            'priority': todo.priority, 'version': todo.version
        }
        cache.set(cache_key, data, timeout=300)
        return JsonResponse(data)
    except Todo.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)

@extend_schema(summary="Update Todo", tags=["Todos"])
@csrf_protect
@require_http_methods(["PATCH"])
def todo_update(request, todo_id):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    try:
        todo = Todo.objects.select_for_update().get(id=todo_id, list__user=user)
        data = json.loads(request.body)
        data.pop('list_id', None)  # Security: prevent list_id changes
        
        serializer = TodoSerializer(data)
        validated_data = serializer.validate()
        
        if not validated_data:
            return JsonResponse({'errors': serializer.errors}, status=400)
        
        with transaction.atomic():
            for k, v in validated_data.items():
                if k != 'list_id' and v is not None:
                    setattr(todo, k, v)
            todo.version += 1
            todo.save()
            cache.delete_many([f'user_todos:{user.id}*', f'todo_detail:{todo_id}:{user.id}'])
            
        return JsonResponse({'id': str(todo.id), 'version': todo.version})
    except Todo.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    except Exception as e:
        logger.error(f"Todo update error: {e}")
        return JsonResponse({'error': 'Update failed'}, status=500)

@extend_schema(summary="Delete Todo", tags=["Todos"])
@csrf_protect
@require_http_methods(["DELETE"])
def todo_delete(request, todo_id):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    try:
        with transaction.atomic():
            todo = Todo.objects.select_for_update().get(id=todo_id, list__user=user)
            todo.delete()
            cache.delete_many([f'user_todos:{user.id}*', f'todo_detail:{todo_id}:{user.id}'])
        return JsonResponse({}, status=204)
    except Todo.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)

@extend_schema(summary="Toggle Todo", tags=["Todos"])
@csrf_protect
@require_http_methods(["POST"])
def todo_toggle(request, todo_id):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    try:
        with transaction.atomic():
            todo = Todo.objects.select_for_update().get(id=todo_id, list__user=user)
            todo.status = 'done' if todo.status == 'open' else 'open'
            todo.version += 1
            todo.save()
            cache.delete_many([f'user_todos:{user.id}*', f'todo_detail:{todo_id}:{user.id}'])
            
        return JsonResponse({'id': str(todo.id), 'status': todo.status, 'version': todo.version})
    except Todo.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)

@extend_schema(summary="Bulk Operations", tags=["Todos"])
@csrf_protect
@require_http_methods(["POST"])
def todos_bulk(request):
    user = get_user_from_cache(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    try:
        data = json.loads(request.body)
        operations = data.get('operations', [])
        
        if len(operations) > 100:
            return JsonResponse({'error': 'Too many operations'}, status=400)
        
        results = []
        
        with transaction.atomic():
            for op in operations:
                op_type = op.get('type')
                
                if op_type == 'create':
                    try:
                        list_obj = List.objects.get(id=op['list_id'], user=user)
                        todo = Todo.objects.create(list=list_obj, title=op['title'])
                        results.append({'type': 'created', 'id': str(todo.id)})
                    except (List.DoesNotExist, KeyError):
                        results.append({'type': 'error', 'message': 'Invalid create operation'})
                        
                elif op_type == 'delete':
                    try:
                        Todo.objects.filter(id=op['id'], list__user=user).delete()
                        results.append({'type': 'deleted', 'id': op['id']})
                    except KeyError:
                        results.append({'type': 'error', 'message': 'Invalid delete operation'})
            
            cache.delete_many([f'user_todos:{user.id}*'])
        
        return JsonResponse({'results': results})
    except Exception as e:
        logger.error(f"Bulk operations error: {e}")
        return JsonResponse({'error': 'Bulk operation failed'}, status=500)