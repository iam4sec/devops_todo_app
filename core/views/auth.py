import json
from datetime import datetime, timedelta
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.middleware.csrf import get_token
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from django.http import JsonResponse
from ..models import User, Session
from ..utils import json_response, error_response, create_session
from ..validators import InputValidator, log_security_event

@require_http_methods(["GET"])
def csrf_token(request):
    return json_response({'csrfToken': get_token(request)})

@csrf_exempt
@require_http_methods(["POST"])
def login(request):
    ip = get_client_ip(request)
    attempts_key = f"login_attempts:{ip}"
    
    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
        
        # Validate input
        email = InputValidator.validate_email(email)
        if not password or len(password) > 128:
            raise ValueError("Invalid password")
        
        user = authenticate(request, username=email, password=password)
        if not user:
            # Increment failed attempts
            attempts = cache.get(attempts_key, 0) + 1
            cache.set(attempts_key, attempts, 3600)  # 1 hour
            
            log_security_event('LOGIN_FAILED', ip=ip, details=f"Email: {email}")
            return error_response('UNAUTHENTICATED', 'Invalid credentials', status=401)
        
        # Clear failed attempts on successful login
        cache.delete(attempts_key)
        
        # Check for concurrent sessions
        active_sessions = Session.objects.filter(user=user, expires_at__gt=timezone.now()).count()
        if active_sessions >= 3:  # Max 3 concurrent sessions
            log_security_event('MAX_SESSIONS_EXCEEDED', user_id=str(user.id), ip=ip)
            return error_response('TOO_MANY_SESSIONS', 'Maximum sessions exceeded', status=429)
        
        session = create_session(user, request)
        log_security_event('LOGIN_SUCCESS', user_id=str(user.id), ip=ip)
        
        response = json_response({'user_id': str(user.id)})
        response.set_cookie('sid', str(session.id), max_age=settings.SESSION_COOKIE_AGE, 
                          httponly=True, secure=not settings.DEBUG, samesite='Lax')
        response.set_cookie('refresh', str(session.id), max_age=2592000, httponly=True,
                          secure=not settings.DEBUG, samesite='Strict', path='/auth/refresh')
        return response
    except Exception as e:
        log_security_event('LOGIN_ERROR', ip=ip, details=str(e))
        return error_response('VALIDATION_ERROR', 'Invalid request')

@require_http_methods(["POST"])
def refresh(request):
    refresh_token = request.COOKIES.get('refresh')
    if not refresh_token:
        return error_response('UNAUTHENTICATED', 'No refresh token', status=401)
    
    try:
        InputValidator.validate_uuid(refresh_token)
        session = Session.objects.get(id=refresh_token, expires_at__gt=timezone.now())
        
        # Validate session IP and user agent for security
        current_ip = get_client_ip(request)
        if session.ip != current_ip:
            log_security_event('SESSION_IP_MISMATCH', user_id=str(session.user.id), 
                             ip=current_ip, details=f"Original IP: {session.ip}")
            Session.objects.filter(user=session.user).delete()  # Invalidate all sessions
            return error_response('SECURITY_VIOLATION', 'Session invalidated', status=401)
        
        new_session = create_session(session.user, request)
        session.delete()  # Remove old session
        
        response = json_response({'refreshed': True})
        response.set_cookie('sid', str(new_session.id), max_age=settings.SESSION_COOKIE_AGE,
                          httponly=True, secure=not settings.DEBUG, samesite='Lax')
        response.set_cookie('refresh', str(new_session.id), max_age=2592000, httponly=True,
                          secure=not settings.DEBUG, samesite='Strict', path='/auth/refresh')
        return response
    except (Session.DoesNotExist, ValueError):
        log_security_event('INVALID_REFRESH_TOKEN', ip=get_client_ip(request))
        return error_response('UNAUTHENTICATED', 'Invalid refresh token', status=401)

@require_http_methods(["POST"])
def logout(request):
    sid = request.COOKIES.get('sid')
    if sid:
        try:
            session = Session.objects.get(id=sid)
            log_security_event('LOGOUT', user_id=str(session.user.id), ip=get_client_ip(request))
            session.delete()
        except Session.DoesNotExist:
            pass
    
    response = json_response({'logged_out': True})
    response.delete_cookie('sid')
    response.delete_cookie('refresh', path='/auth/refresh')
    return response

def csrf_failure(request, reason=""):
    log_security_event('CSRF_FAILURE', ip=get_client_ip(request), details=reason)
    return JsonResponse({'error': {'code': 'CSRF_FAILURE', 'message': 'CSRF verification failed'}}, status=403)

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')