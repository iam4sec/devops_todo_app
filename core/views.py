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
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.openapi import OpenApiTypes
from .models import User, Session, List, Todo
from .serializers import LoginSerializer, ListSerializer, TodoSerializer

logger = logging.getLogger(__name__)

# Root endpoint
@extend_schema(
    summary="API Information",
    description="Get basic API information and available endpoints",
    tags=["Info"],
    responses={
        200: {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "version": {"type": "string"},
                "docs": {"type": "string"}
            }
        }
    }
)
@require_http_methods(["GET"])
def api_info(request):
    return JsonResponse({
        'name': 'Todo App API',
        'version': '1.0.0',
        'docs': '/api/docs/'
    })

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
class CSRFTokenView(APIView):
    @extend_schema(
        summary="Get CSRF Token",
        description="Retrieve CSRF token for authenticated requests",
        tags=["Auth"],
        responses={
            200: {
                "type": "object",
                "properties": {
                    "csrfToken": {"type": "string", "description": "CSRF token"}
                }
            }
        }
    )
    def get(self, request):
        return Response({'csrfToken': get_token(request)})

# Keep function-based view for backward compatibility
@ensure_csrf_cookie
@require_http_methods(["GET"])
def csrf_token(request):
    view = CSRFTokenView()
    view.request = request
    return view.get(request)

class RegisterView(APIView):
    @extend_schema(
        summary="User Registration",
        description="Register a new user account",
        tags=["Auth"],
        request={
            "type": "object",
            "properties": {
                "email": {"type": "string", "format": "email", "description": "User email"},
                "password": {"type": "string", "minLength": 8, "description": "User password"},
                "password_confirm": {"type": "string", "description": "Password confirmation"}
            },
            "required": ["email", "password", "password_confirm"]
        },
        responses={
            201: {
                "type": "object",
                "properties": {
                    "user_id": {"type": "string", "format": "uuid", "description": "User ID"},
                    "email": {"type": "string", "format": "email", "description": "User email"}
                }
            },
            400: {
                "type": "object",
                "properties": {
                    "errors": {"type": "object", "description": "Validation errors"}
                }
            }
        }
    )
    def post(self, request):
        try:
            data = request.data if hasattr(request, 'data') else json.loads(request.body)
            
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')
            password_confirm = data.get('password_confirm', '')
            
            errors = {}
            
            if not email or '@' not in email:
                errors['email'] = 'Valid email is required'
            elif User.objects.filter(email=email).exists():
                errors['email'] = 'Email already registered'
                
            if len(password) < 8:
                errors['password'] = 'Password must be at least 8 characters'
                
            if password != password_confirm:
                errors['password_confirm'] = 'Passwords do not match'
                
            if errors:
                return Response({'errors': errors}, status=status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic():
                user = User.objects.create_user(email=email, password=password)
                
            return Response({
                'user_id': str(user.id),
                'email': user.email
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return Response({'error': 'Registration failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginView(APIView):
    @extend_schema(
        summary="User Login",
        description="Authenticate user and create session",
        tags=["Auth"],
        request={
            "type": "object",
            "properties": {
                "email": {"type": "string", "format": "email", "description": "User email"},
                "password": {"type": "string", "description": "User password"}
            },
            "required": ["email", "password"]
        },
        responses={
            200: {
                "type": "object",
                "properties": {
                    "user_id": {"type": "string", "format": "uuid", "description": "User ID"}
                }
            },
            400: {
                "type": "object",
                "properties": {
                    "errors": {"type": "object", "description": "Validation errors"}
                }
            }
        }
    )
    def post(self, request):
        try:
            data = request.data if hasattr(request, 'data') else json.loads(request.body)
            serializer = LoginSerializer(data)
            validated_data = serializer.validate()
            
            if not validated_data:
                return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            
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
            
            response = Response({'user_id': str(user.id)})
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
            return Response({'error': 'Invalid JSON'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Login error: {e}")
            return Response({'error': 'Login failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Keep function-based view for backward compatibility
def login(request):
    view = LoginView()
    view.request = request
    return view.post(request)

class LogoutView(APIView):
    @extend_schema(
        summary="User Logout",
        description="Logout user and destroy session",
        tags=["Auth"],
        responses={
            200: {
                "type": "object",
                "properties": {
                    "logged_out": {"type": "boolean", "description": "Logout status"}
                }
            }
        }
    )
    def post(self, request):
        sid = request.COOKIES.get('sid')
        if sid:
            Session.objects.filter(id=sid).delete()
            cache.delete(f'session:{sid}')
            logger.info(f"User logged out, session {sid} deleted")
        
        response = Response({'logged_out': True})
        response.delete_cookie('sid')
        return response

# Keep function-based view for backward compatibility
def logout(request):
    view = LogoutView()
    view.request = request
    return view.post(request)

class RefreshView(APIView):
    @extend_schema(
        summary="Refresh Session",
        description="Refresh user session and extend expiry",
        tags=["Auth"],
        responses={
            200: {
                "type": "object",
                "properties": {
                    "refreshed": {"type": "boolean", "description": "Session refresh status"}
                }
            },
            401: {
                "type": "object",
                "properties": {
                    "error": {"type": "string"}
                }
            }
        }
    )
    def post(self, request):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        sid = request.COOKIES.get('sid')
        if sid:
            try:
                session = Session.objects.get(id=sid, user=user)
                session.expires_at = timezone.now() + timedelta(seconds=settings.SESSION_COOKIE_AGE)
                session.save()
                
                # Update cache
                cache.set(f'session:{sid}', {
                    'user_id': user.id,
                    'expires_at': session.expires_at,
                    'ip': session.ip
                }, timeout=settings.SESSION_COOKIE_AGE)
                
                response = Response({'refreshed': True})
                response.set_cookie(
                    'sid', str(session.id),
                    max_age=settings.SESSION_COOKIE_AGE,
                    httponly=True,
                    secure=not settings.DEBUG,
                    samesite='Lax'
                )
                return response
            except Session.DoesNotExist:
                pass
        
        return Response({'error': 'Session not found'}, status=status.HTTP_401_UNAUTHORIZED)

def refresh(request):
    view = RefreshView()
    view.request = request
    return view.post(request)

# API Views
class MeView(APIView):
    @extend_schema(
        summary="Current User Profile",
        description="Get current authenticated user information",
        tags=["User"],
        responses={
            200: {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid", "description": "User ID"},
                    "email": {"type": "string", "format": "email", "description": "User email"}
                }
            },
            401: {
                "type": "object",
                "properties": {
                    "error": {"type": "string", "description": "Error message"}
                }
            }
        }
    )
    def get(self, request):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response({'id': str(user.id), 'email': user.email})

# Keep function-based view for backward compatibility
def me(request):
    view = MeView()
    view.request = request
    return view.get(request)

class ListsView(APIView):
    @extend_schema(
        summary="Get Lists",
        description="Retrieve user's todo lists with optional search and pagination",
        tags=["Lists"],
        parameters=[
            OpenApiParameter("q", OpenApiTypes.STR, description="Search query for list names"),
            OpenApiParameter("cursor", OpenApiTypes.STR, description="Pagination cursor")
        ],
        responses={
            200: {
                "type": "object",
                "properties": {
                    "data": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string", "format": "uuid"},
                                "name": {"type": "string"},
                                "color": {"type": "string", "nullable": True},
                                "todo_count": {"type": "integer", "description": "Number of todos in list"}
                            }
                        }
                    },
                    "next_cursor": {"type": "string", "nullable": True}
                }
            }
        }
    )
    def get(self, request):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        cache_key = f'user_lists:{user.id}'
        q = request.GET.get('q', '').strip()
        if q:
            cache_key += f':search:{q}'
        
        cached_data = cache.get(cache_key)
        if cached_data:
            return Response(cached_data)
        
        qs = List.objects.filter(user=user).select_related('user').order_by('-created_at')
        if q:
            qs = qs.filter(name__icontains=q)
        
        items, cursor = paginate(qs, request)
        data = {
            'data': [{
                'id': str(l.id), 
                'name': l.name, 
                'color': l.color,
                'todo_count': l.todos.count()
            } for l in items],
            'next_cursor': cursor
        }
        
        cache.set(cache_key, data, timeout=300)
        return Response(data)
    
    @extend_schema(
        summary="Create List",
        description="Create a new todo list",
        tags=["Lists"],
        request={
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 255, "description": "List name"},
                "color": {"type": "string", "pattern": "^#[0-9A-Fa-f]{6}$", "description": "Hex color code"}
            },
            "required": ["name"]
        },
        responses={
            201: {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "name": {"type": "string"},
                    "color": {"type": "string", "nullable": True},
                    "todo_count": {"type": "integer"}
                }
            }
        }
    )
    def post(self, request):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            data = request.data if hasattr(request, 'data') else json.loads(request.body)
            serializer = ListSerializer(data)
            validated_data = serializer.validate()
            
            if not validated_data:
                return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic():
                list_obj = List.objects.create(user=user, **validated_data)
                cache.delete_many([f'user_lists:{user.id}*'])
                
            return Response({
                'id': str(list_obj.id), 
                'name': list_obj.name, 
                'color': list_obj.color,
                'todo_count': 0
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"List creation error: {e}")
            return Response({'error': 'Creation failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Keep function-based view for backward compatibility
def lists(request):
    view = ListsView()
    view.request = request
    if request.method == 'GET':
        return view.get(request)
    elif request.method == 'POST':
        return view.post(request)



class ListDetailView(APIView):
    @extend_schema(
        summary="Get List Detail",
        description="Retrieve specific list information with todos",
        tags=["Lists"],
        responses={
            200: {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "name": {"type": "string"},
                    "color": {"type": "string", "nullable": True},
                    "todo_count": {"type": "integer"},
                    "todos": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string", "format": "uuid"},
                                "title": {"type": "string"},
                                "status": {"type": "string", "enum": ["open", "doing", "done"]},
                                "priority": {"type": "integer"}
                            }
                        }
                    }
                }
            },
            404: {
                "type": "object",
                "properties": {
                    "error": {"type": "string"}
                }
            }
        }
    )
    def get(self, request, list_id):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            list_obj = List.objects.prefetch_related('todos').get(id=list_id, user=user)
            todos = list_obj.todos.all().order_by('-created_at')[:20]  # Limit to 20 recent todos
            
            data = {
                'id': str(list_obj.id), 
                'name': list_obj.name, 
                'color': list_obj.color,
                'todo_count': list_obj.todos.count(),
                'todos': [{
                    'id': str(t.id),
                    'title': t.title,
                    'status': t.status,
                    'priority': t.priority
                } for t in todos]
            }
            return Response(data)
        except List.DoesNotExist:
            return Response({'error': 'List not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @extend_schema(
        summary="Update List",
        description="Update list name or color",
        tags=["Lists"],
        request={
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 255},
                "color": {"type": "string", "pattern": "^#[0-9A-Fa-f]{6}$"}
            }
        },
        responses={
            200: {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "name": {"type": "string"},
                    "color": {"type": "string", "nullable": True}
                }
            }
        }
    )
    def put(self, request, list_id):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            list_obj = List.objects.select_for_update().get(id=list_id, user=user)
            data = request.data if hasattr(request, 'data') else json.loads(request.body)
            serializer = ListSerializer(data)
            validated_data = serializer.validate()
            
            if not validated_data:
                return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic():
                for k, v in validated_data.items():
                    if v is not None:
                        setattr(list_obj, k, v)
                list_obj.save()
                cache.delete_many([f'user_lists:{user.id}*', f'list_detail:{list_id}:{user.id}'])
                
            return Response({'id': str(list_obj.id), 'name': list_obj.name, 'color': list_obj.color})
        except List.DoesNotExist:
            return Response({'error': 'List not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"List update error: {e}")
            return Response({'error': 'Update failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @extend_schema(
        summary="Delete List",
        description="Delete a todo list and all its todos",
        tags=["Lists"],
        responses={
            204: {"description": "List deleted successfully"},
            404: {
                "type": "object",
                "properties": {
                    "error": {"type": "string"}
                }
            }
        }
    )
    def delete(self, request, list_id):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            with transaction.atomic():
                list_obj = List.objects.select_for_update().get(id=list_id, user=user)
                list_obj.delete()
                cache.delete_many([f'user_lists:{user.id}*', f'list_detail:{list_id}:{user.id}'])
            return Response(status=status.HTTP_204_NO_CONTENT)
        except List.DoesNotExist:
            return Response({'error': 'List not found'}, status=status.HTTP_404_NOT_FOUND)

def list_detail(request, list_id):
    view = ListDetailView()
    view.request = request
    if request.method == 'GET':
        return view.get(request, list_id)
    elif request.method == 'PUT':
        return view.put(request, list_id)
    elif request.method == 'DELETE':
        return view.delete(request, list_id)



class TodosView(APIView):
    @extend_schema(
        summary="Get Todos",
        description="Retrieve todos with filtering and pagination",
        tags=["Todos"],
        parameters=[
            OpenApiParameter("list_id", OpenApiTypes.UUID, description="Filter by list ID"),
            OpenApiParameter("status", OpenApiTypes.STR, description="Filter by status (open, doing, done)"),
            OpenApiParameter("q", OpenApiTypes.STR, description="Search query for todo titles"),
            OpenApiParameter("cursor", OpenApiTypes.STR, description="Pagination cursor")
        ],
        responses={
            200: {
                "type": "object",
                "properties": {
                    "data": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string", "format": "uuid"},
                                "list_id": {"type": "string", "format": "uuid"},
                                "list_name": {"type": "string", "description": "Name of the list"},
                                "title": {"type": "string"},
                                "status": {"type": "string", "enum": ["open", "doing", "done"]},
                                "priority": {"type": "integer", "minimum": 1, "maximum": 5},
                                "created_at": {"type": "string", "format": "date-time"},
                                "updated_at": {"type": "string", "format": "date-time"}
                            }
                        }
                    },
                    "next_cursor": {"type": "string", "nullable": True}
                }
            }
        }
    )
    def get(self, request):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        filters = {
            'list_id': request.GET.get('list_id'),
            'status': request.GET.get('status'),
            'q': request.GET.get('q', '').strip()
        }
        cache_key = f'user_todos:{user.id}:' + ':'.join(f'{k}={v}' for k, v in filters.items() if v)
        
        cached_data = cache.get(cache_key)
        if cached_data:
            return Response(cached_data)
        
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
                'id': str(t.id), 
                'list_id': str(t.list_id), 
                'list_name': t.list.name,
                'title': t.title,
                'status': t.status, 
                'priority': t.priority,
                'created_at': t.created_at.isoformat(),
                'updated_at': t.updated_at.isoformat()
            } for t in items],
            'next_cursor': cursor
        }
        
        cache.set(cache_key, data, timeout=120)
        return Response(data)
    
    @extend_schema(
        summary="Create Todo",
        description="Create a new todo item",
        tags=["Todos"],
        request={
            "type": "object",
            "properties": {
                "list_id": {"type": "string", "format": "uuid", "description": "List ID"},
                "title": {"type": "string", "maxLength": 255, "description": "Todo title"},
                "status": {"type": "string", "enum": ["open", "doing", "done"], "default": "open"},
                "priority": {"type": "integer", "minimum": 1, "maximum": 5, "default": 3}
            },
            "required": ["list_id", "title"]
        },
        responses={
            201: {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "title": {"type": "string"},
                    "status": {"type": "string"},
                    "priority": {"type": "integer"},
                    "list_name": {"type": "string"}
                }
            }
        }
    )
    def post(self, request):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            data = request.data if hasattr(request, 'data') else json.loads(request.body)
            serializer = TodoSerializer(data)
            validated_data = serializer.validate()
            
            if not validated_data:
                return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            
            list_obj = List.objects.get(id=validated_data['list_id'], user=user)
            with transaction.atomic():
                todo_data = {k: v for k, v in validated_data.items() if k != 'list_id'}
                todo = Todo.objects.create(list=list_obj, **todo_data)
                cache.delete_many([f'user_todos:{user.id}*'])
                
            return Response({
                'id': str(todo.id), 
                'title': todo.title, 
                'status': todo.status,
                'priority': todo.priority,
                'list_name': list_obj.name
            }, status=status.HTTP_201_CREATED)
        except List.DoesNotExist:
            return Response({'error': 'List not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Todo creation error: {e}")
            return Response({'error': 'Creation failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def todos(request):
    view = TodosView()
    view.request = request
    if request.method == 'GET':
        return view.get(request)
    elif request.method == 'POST':
        return view.post(request)



class TodoDetailView(APIView):
    @extend_schema(
        summary="Get Todo Detail",
        description="Retrieve specific todo information",
        tags=["Todos"],
        responses={
            200: {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "title": {"type": "string"},
                    "status": {"type": "string", "enum": ["open", "doing", "done"]},
                    "priority": {"type": "integer", "minimum": 1, "maximum": 5},
                    "list_id": {"type": "string", "format": "uuid"},
                    "list_name": {"type": "string"},
                    "created_at": {"type": "string", "format": "date-time"},
                    "updated_at": {"type": "string", "format": "date-time"}
                }
            },
            404: {
                "type": "object",
                "properties": {
                    "error": {"type": "string"}
                }
            }
        }
    )
    def get(self, request, todo_id):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            todo = Todo.objects.select_related('list').get(id=todo_id, list__user=user)
            data = {
                'id': str(todo.id), 
                'title': todo.title, 
                'status': todo.status,
                'priority': todo.priority,
                'list_id': str(todo.list_id),
                'list_name': todo.list.name,
                'created_at': todo.created_at.isoformat(),
                'updated_at': todo.updated_at.isoformat()
            }
            return Response(data)
        except Todo.DoesNotExist:
            return Response({'error': 'Todo not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @extend_schema(
        summary="Update Todo",
        description="Update todo properties (title, status, priority)",
        tags=["Todos"],
        request={
            "type": "object",
            "properties": {
                "title": {"type": "string", "maxLength": 255},
                "status": {"type": "string", "enum": ["open", "doing", "done"]},
                "priority": {"type": "integer", "minimum": 1, "maximum": 5}
            }
        },
        responses={
            200: {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "title": {"type": "string"},
                    "status": {"type": "string"},
                    "priority": {"type": "integer"}
                }
            }
        }
    )
    def put(self, request, todo_id):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            todo = Todo.objects.select_for_update().get(id=todo_id, list__user=user)
            data = request.data if hasattr(request, 'data') else json.loads(request.body)
            data.pop('list_id', None)  # Security: prevent list_id changes
            
            serializer = TodoSerializer(data)
            validated_data = serializer.validate()
            
            if not validated_data:
                return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic():
                for k, v in validated_data.items():
                    if k != 'list_id' and v is not None:
                        setattr(todo, k, v)
                todo.version += 1
                todo.save()
                cache.delete_many([f'user_todos:{user.id}*', f'todo_detail:{todo_id}:{user.id}'])
                
            return Response({
                'id': str(todo.id), 
                'title': todo.title,
                'status': todo.status,
                'priority': todo.priority
            })
        except Todo.DoesNotExist:
            return Response({'error': 'Todo not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Todo update error: {e}")
            return Response({'error': 'Update failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @extend_schema(
        summary="Delete Todo",
        description="Delete a todo item",
        tags=["Todos"],
        responses={
            204: {"description": "Todo deleted successfully"},
            404: {
                "type": "object",
                "properties": {
                    "error": {"type": "string"}
                }
            }
        }
    )
    def delete(self, request, todo_id):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            with transaction.atomic():
                todo = Todo.objects.select_for_update().get(id=todo_id, list__user=user)
                todo.delete()
                cache.delete_many([f'user_todos:{user.id}*', f'todo_detail:{todo_id}:{user.id}'])
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Todo.DoesNotExist:
            return Response({'error': 'Todo not found'}, status=status.HTTP_404_NOT_FOUND)

def todo_detail(request, todo_id):
    view = TodoDetailView()
    view.request = request
    if request.method == 'GET':
        return view.get(request, todo_id)
    elif request.method == 'PUT':
        return view.put(request, todo_id)
    elif request.method == 'DELETE':
        return view.delete(request, todo_id)



class TodoToggleView(APIView):
    @extend_schema(
        summary="Toggle Todo Status",
        description="Toggle todo status between open and done",
        tags=["Todos"],
        responses={
            200: {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "status": {"type": "string", "enum": ["open", "done"]},
                    "version": {"type": "integer"}
                }
            },
            404: {
                "type": "object",
                "properties": {
                    "error": {"type": "string"}
                }
            }
        }
    )
    def post(self, request, todo_id):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            with transaction.atomic():
                todo = Todo.objects.select_for_update().get(id=todo_id, list__user=user)
                todo.status = 'done' if todo.status == 'open' else 'open'
                todo.version += 1
                todo.save()
                cache.delete_many([f'user_todos:{user.id}*', f'todo_detail:{todo_id}:{user.id}'])
                
            return Response({'id': str(todo.id), 'status': todo.status, 'version': todo.version})
        except Todo.DoesNotExist:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)

def todo_toggle(request, todo_id):
    view = TodoToggleView()
    view.request = request
    return view.post(request, todo_id)

class TodosBulkView(APIView):
    @extend_schema(
        summary="Bulk Todo Operations",
        description="Perform bulk create/delete operations on todos",
        tags=["Todos"],
        request={
            "type": "object",
            "properties": {
                "operations": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {
                        "oneOf": [
                            {
                                "type": "object",
                                "properties": {
                                    "type": {"type": "string", "enum": ["create"]},
                                    "list_id": {"type": "string", "format": "uuid"},
                                    "title": {"type": "string", "maxLength": 255}
                                },
                                "required": ["type", "list_id", "title"]
                            },
                            {
                                "type": "object",
                                "properties": {
                                    "type": {"type": "string", "enum": ["delete"]},
                                    "id": {"type": "string", "format": "uuid"}
                                },
                                "required": ["type", "id"]
                            }
                        ]
                    }
                }
            },
            "required": ["operations"]
        },
        responses={
            200: {
                "type": "object",
                "properties": {
                    "results": {
                        "type": "array",
                        "items": {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "properties": {
                                        "type": {"type": "string", "enum": ["created"]},
                                        "id": {"type": "string", "format": "uuid"}
                                    }
                                },
                                {
                                    "type": "object",
                                    "properties": {
                                        "type": {"type": "string", "enum": ["deleted"]},
                                        "id": {"type": "string", "format": "uuid"}
                                    }
                                },
                                {
                                    "type": "object",
                                    "properties": {
                                        "type": {"type": "string", "enum": ["error"]},
                                        "message": {"type": "string"}
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }
    )
    def post(self, request):
        user = get_user_from_cache(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            data = request.data if hasattr(request, 'data') else json.loads(request.body)
            operations = data.get('operations', [])
            
            if len(operations) > 100:
                return Response({'error': 'Too many operations'}, status=status.HTTP_400_BAD_REQUEST)
            
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
            
            return Response({'results': results})
        except Exception as e:
            logger.error(f"Bulk operations error: {e}")
            return Response({'error': 'Bulk operation failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def todos_bulk(request):
    view = TodosBulkView()
    view.request = request
    return view.post(request)