import json
from datetime import datetime, timedelta
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.middleware.csrf import get_token
from django.utils import timezone
from ..models import User, Session
from ..utils import json_response, error_response, create_session

@require_http_methods(["GET"])
def csrf_token(request):
    return json_response({'csrfToken': get_token(request)})

@csrf_exempt
@require_http_methods(["POST"])
def login(request):
    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
        
        user = authenticate(request, username=email, password=password)
        if not user:
            return error_response('UNAUTHENTICATED', 'Invalid credentials', status=401)
        
        session = create_session(user, request)
        
        response = json_response({'user_id': str(user.id)})
        response.set_cookie('sid', str(session.id), max_age=900, httponly=True, 
                          secure=not request.META.get('HTTP_HOST', '').startswith('localhost'),
                          samesite='Lax')
        response.set_cookie('refresh', str(session.id), max_age=2592000, httponly=True,
                          secure=not request.META.get('HTTP_HOST', '').startswith('localhost'),
                          samesite='Strict', path='/auth/refresh')
        return response
    except Exception as e:
        return error_response('VALIDATION_ERROR', str(e))

@require_http_methods(["POST"])
def refresh(request):
    refresh_token = request.COOKIES.get('refresh')
    if not refresh_token:
        return error_response('UNAUTHENTICATED', 'No refresh token', status=401)
    
    try:
        session = Session.objects.get(id=refresh_token, expires_at__gt=timezone.now())
        new_session = create_session(session.user, request)
        
        response = json_response({'refreshed': True})
        response.set_cookie('sid', str(new_session.id), max_age=900, httponly=True,
                          secure=not request.META.get('HTTP_HOST', '').startswith('localhost'),
                          samesite='Lax')
        response.set_cookie('refresh', str(new_session.id), max_age=2592000, httponly=True,
                          secure=not request.META.get('HTTP_HOST', '').startswith('localhost'),
                          samesite='Strict', path='/auth/refresh')
        return response
    except Session.DoesNotExist:
        return error_response('UNAUTHENTICATED', 'Invalid refresh token', status=401)

@require_http_methods(["POST"])
def logout(request):
    sid = request.COOKIES.get('sid')
    if sid:
        Session.objects.filter(id=sid).delete()
    
    response = json_response({'logged_out': True})
    response.delete_cookie('sid')
    response.delete_cookie('refresh', path='/auth/refresh')
    return response