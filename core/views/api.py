import json
import base64
import re
from datetime import datetime
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ValidationError
from ..models import User, Session, List, Todo
from ..utils import json_response, error_response, check_idempotency, save_idempotency
from ..validators import InputValidator, log_security_event

def get_user_from_session(request):
    sid = request.COOKIES.get('sid')
    if not sid:
        return None
    try:
        InputValidator.validate_uuid(sid)
        session = Session.objects.select_related('user').get(id=sid, expires_at__gt=timezone.now())
        
        # Validate session IP for security
        current_ip = get_client_ip(request)
        if session.ip != current_ip:
            log_security_event('SESSION_IP_MISMATCH', user_id=str(session.user.id), 
                             ip=current_ip, details=f"Original IP: {session.ip}")
            session.delete()
            return None
            
        return session.user
    except (Session.DoesNotExist, ValidationError):
        return None

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

@require_http_methods(["GET"])
def me(request):
    user = get_user_from_session(request)
    if not user:
        return error_response('UNAUTHENTICATED', 'Not authenticated', status=401)
    
    return json_response({
        'id': str(user.id),
        'email': user.email,
        'created_at': user.created_at.isoformat()
    })

@require_http_methods(["GET", "POST"])
def lists(request):
    user = get_user_from_session(request)
    if not user:
        return error_response('UNAUTHENTICATED', 'Not authenticated', status=401)
    
    if request.method == 'GET':
        limit = int(request.GET.get('limit', 50))
        cursor = request.GET.get('cursor')
        q = request.GET.get('q', '')
        
        queryset = List.objects.filter(user=user)
        if q:
            queryset = queryset.filter(name__icontains=q)
        
        if cursor:
            try:
                cursor_data = json.loads(base64.b64decode(cursor))
                queryset = queryset.filter(id__gt=cursor_data['id'])
            except:
                pass
        
        lists_data = list(queryset.order_by('id')[:limit])
        next_cursor = None
        if len(lists_data) == limit:
            last_id = str(lists_data[-1].id)
            next_cursor = base64.b64encode(json.dumps({'id': last_id}).encode()).decode()
        
        return json_response({
            'data': [{
                'id': str(l.id),
                'name': l.name,
                'color': l.color,
                'created_at': l.created_at.isoformat()
            } for l in lists_data],
            'next_cursor': next_cursor
        })
    
    # POST
    idem_key = request.headers.get('Idempotency-Key')
    if idem_key:
        cached = check_idempotency(idem_key)
        if cached:
            return json_response(cached, status=201)
    
    try:
        data = json.loads(request.body)
        
        # Validate input
        name = InputValidator.sanitize_text(data.get('name', ''), 255)
        if not name or len(name.strip()) == 0:
            raise ValidationError("List name is required")
        
        color = data.get('color')
        if color and not re.match(r'^#[0-9A-Fa-f]{6}$', color):
            raise ValidationError("Invalid color format")
        
        list_obj = List.objects.create(
            user=user,
            name=name,
            color=color
        )
        
        response_data = {
            'id': str(list_obj.id),
            'name': list_obj.name,
            'color': list_obj.color,
            'created_at': list_obj.created_at.isoformat()
        }
        
        if idem_key:
            save_idempotency(idem_key, response_data)
        
        return json_response(response_data, status=201)
    except Exception as e:
        return error_response('VALIDATION_ERROR', str(e))

@require_http_methods(["GET", "PATCH", "DELETE"])
def list_detail(request, list_id):
    user = get_user_from_session(request)
    if not user:
        return error_response('UNAUTHENTICATED', 'Not authenticated', status=401)
    
    try:
        list_obj = List.objects.get(id=list_id, user=user)
    except List.DoesNotExist:
        return error_response('NOT_FOUND', 'List not found', status=404)
    
    if request.method == 'GET':
        return json_response({
            'id': str(list_obj.id),
            'name': list_obj.name,
            'color': list_obj.color,
            'created_at': list_obj.created_at.isoformat(),
            'updated_at': list_obj.updated_at.isoformat()
        })
    
    elif request.method == 'PATCH':
        try:
            data = json.loads(request.body)
            if 'name' in data:
                name = InputValidator.sanitize_text(data['name'], 255)
                if not name or len(name.strip()) == 0:
                    raise ValidationError("List name is required")
                list_obj.name = name
            if 'color' in data:
                color = data['color']
                if color and not re.match(r'^#[0-9A-Fa-f]{6}$', color):
                    raise ValidationError("Invalid color format")
                list_obj.color = color
            list_obj.save()
            
            return json_response({
                'id': str(list_obj.id),
                'name': list_obj.name,
                'color': list_obj.color,
                'updated_at': list_obj.updated_at.isoformat()
            })
        except Exception as e:
            return error_response('VALIDATION_ERROR', str(e))
    
    elif request.method == 'DELETE':
        list_obj.delete()
        return json_response({}, status=204)

@require_http_methods(["GET", "POST"])
def todos(request):
    user = get_user_from_session(request)
    if not user:
        return error_response('UNAUTHENTICATED', 'Not authenticated', status=401)
    
    if request.method == 'GET':
        limit = int(request.GET.get('limit', 50))
        cursor = request.GET.get('cursor')
        list_id = request.GET.get('list_id')
        status = request.GET.get('status')
        priority = request.GET.get('priority')
        due_before = request.GET.get('due_before')
        q = request.GET.get('q', '')
        
        queryset = Todo.objects.filter(list__user=user)
        if list_id:
            queryset = queryset.filter(list_id=list_id)
        if status:
            queryset = queryset.filter(status=status)
        if priority:
            queryset = queryset.filter(priority=int(priority))
        if due_before:
            queryset = queryset.filter(due_date__lt=due_before)
        if q:
            queryset = queryset.filter(title__icontains=q)
        
        if cursor:
            try:
                cursor_data = json.loads(base64.b64decode(cursor))
                queryset = queryset.filter(id__gt=cursor_data['id'])
            except:
                pass
        
        todos_data = list(queryset.order_by('id')[:limit])
        next_cursor = None
        if len(todos_data) == limit:
            last_id = str(todos_data[-1].id)
            next_cursor = base64.b64encode(json.dumps({'id': last_id}).encode()).decode()
        
        return json_response({
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
            } for t in todos_data],
            'next_cursor': next_cursor
        })
    
    # POST
    try:
        data = json.loads(request.body)
        
        # Validate input
        list_id = InputValidator.validate_uuid(data.get('list_id'))
        title = InputValidator.sanitize_text(data.get('title', ''), 255)
        note = InputValidator.sanitize_text(data.get('note', ''), 1000)
        
        if not title or len(title.strip()) == 0:
            raise ValidationError("Todo title is required")
        
        status = data.get('status', 'open')
        if status not in ['open', 'doing', 'done']:
            raise ValidationError("Invalid status")
        
        priority = int(data.get('priority', 3))
        if priority < 1 or priority > 5:
            raise ValidationError("Priority must be between 1 and 5")
        
        list_obj = List.objects.get(id=list_id, user=user)
        
        todo = Todo.objects.create(
            list=list_obj,
            title=title,
            note=note,
            status=status,
            priority=priority,
            due_date=data.get('due_date')
        )
        
        return json_response({
            'id': str(todo.id),
            'list_id': str(todo.list_id),
            'title': todo.title,
            'note': todo.note,
            'status': todo.status,
            'priority': todo.priority,
            'due_date': todo.due_date.isoformat() if todo.due_date else None,
            'version': todo.version,
            'updated_at': todo.updated_at.isoformat()
        }, status=201)
    except Exception as e:
        return error_response('VALIDATION_ERROR', str(e))

@require_http_methods(["GET", "PATCH", "DELETE"])
def todo_detail(request, todo_id):
    user = get_user_from_session(request)
    if not user:
        return error_response('UNAUTHENTICATED', 'Not authenticated', status=401)
    
    try:
        todo = Todo.objects.get(id=todo_id, list__user=user)
    except Todo.DoesNotExist:
        return error_response('NOT_FOUND', 'Todo not found', status=404)
    
    if request.method == 'GET':
        return json_response({
            'id': str(todo.id),
            'list_id': str(todo.list_id),
            'title': todo.title,
            'note': todo.note,
            'status': todo.status,
            'priority': todo.priority,
            'due_date': todo.due_date.isoformat() if todo.due_date else None,
            'version': todo.version,
            'updated_at': todo.updated_at.isoformat()
        })
    
    elif request.method == 'PATCH':
        try:
            data = json.loads(request.body)
            
            if 'title' in data:
                title = InputValidator.sanitize_text(data['title'], 255)
                if not title or len(title.strip()) == 0:
                    raise ValidationError("Todo title is required")
                todo.title = title
            
            if 'note' in data:
                todo.note = InputValidator.sanitize_text(data['note'], 1000)
            
            if 'status' in data:
                status = data['status']
                if status not in ['open', 'doing', 'done']:
                    raise ValidationError("Invalid status")
                todo.status = status
            
            if 'priority' in data:
                priority = int(data['priority'])
                if priority < 1 or priority > 5:
                    raise ValidationError("Priority must be between 1 and 5")
                todo.priority = priority
            
            if 'due_date' in data:
                todo.due_date = data['due_date']
            
            todo.version += 1
            todo.save()
            
            return json_response({
                'id': str(todo.id),
                'list_id': str(todo.list_id),
                'title': todo.title,
                'note': todo.note,
                'status': todo.status,
                'priority': todo.priority,
                'due_date': todo.due_date.isoformat() if todo.due_date else None,
                'version': todo.version,
                'updated_at': todo.updated_at.isoformat()
            })
        except Exception as e:
            return error_response('VALIDATION_ERROR', str(e))
    
    elif request.method == 'DELETE':
        todo.delete()
        return json_response({}, status=204)

@csrf_protect
@require_http_methods(["POST"])
def todo_toggle(request, todo_id):
    user = get_user_from_session(request)
    if not user:
        return error_response('UNAUTHENTICATED', 'Not authenticated', status=401)
    
    try:
        todo = Todo.objects.get(id=todo_id, list__user=user)
        todo.status = 'done' if todo.status == 'open' else 'open'
        todo.version += 1
        todo.save()
        
        return json_response({
            'id': str(todo.id),
            'status': todo.status,
            'version': todo.version
        })
    except Todo.DoesNotExist:
        return error_response('NOT_FOUND', 'Todo not found', status=404)

@csrf_protect
@require_http_methods(["POST"])
def todos_bulk(request):
    user = get_user_from_session(request)
    if not user:
        return error_response('UNAUTHENTICATED', 'Not authenticated', status=401)
    
    try:
        data = json.loads(request.body)
        results = []
        
        with transaction.atomic():
            for operation in data.get('operations', []):
                op_type = operation['type']
                
                if op_type == 'create':
                    list_obj = List.objects.get(id=operation['list_id'], user=user)
                    todo = Todo.objects.create(
                        list=list_obj,
                        title=operation['title'],
                        note=operation.get('note', ''),
                        status=operation.get('status', 'open'),
                        priority=operation.get('priority', 3)
                    )
                    results.append({'type': 'created', 'id': str(todo.id)})
                
                elif op_type == 'update':
                    todo = Todo.objects.get(id=operation['id'], list__user=user)
                    for field in ['title', 'note', 'status', 'priority']:
                        if field in operation:
                            setattr(todo, field, operation[field])
                    todo.version += 1
                    todo.save()
                    results.append({'type': 'updated', 'id': str(todo.id)})
                
                elif op_type == 'delete':
                    Todo.objects.filter(id=operation['id'], list__user=user).delete()
                    results.append({'type': 'deleted', 'id': operation['id']})
        
        return json_response({'results': results})
    except Exception as e:
        return error_response('VALIDATION_ERROR', str(e))