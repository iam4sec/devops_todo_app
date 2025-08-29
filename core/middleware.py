import time
import hashlib
from django.http import JsonResponse
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from .validators import log_security_event

class SecurityMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Check for suspicious patterns
        suspicious_patterns = ['<script', 'javascript:', 'vbscript:', 'onload=', 'onerror=']
        query_string = request.META.get('QUERY_STRING', '').lower()
        
        for pattern in suspicious_patterns:
            if pattern in query_string:
                log_security_event('XSS_ATTEMPT', ip=self.get_client_ip(request), 
                                 details=f"Pattern: {pattern}")
                return JsonResponse({'error': 'Invalid request'}, status=400)
        
        # Request size limits
        content_length = request.META.get('CONTENT_LENGTH')
        if content_length and int(content_length) > settings.DATA_UPLOAD_MAX_MEMORY_SIZE:
            return JsonResponse({'error': 'Request too large'}, status=413)
    
    def process_response(self, request, response):
        response['X-Frame-Options'] = 'DENY'
        response['X-Content-Type-Options'] = 'nosniff'
        response['Referrer-Policy'] = 'no-referrer'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        return response
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

class RateLimitMiddleware(MiddlewareMixin):
    def process_request(self, request):
        ip = self.get_client_ip(request)
        path = request.path
        
        # Check if IP is locked out
        lockout_key = f"lockout:{ip}"
        if cache.get(lockout_key):
            log_security_event('LOCKOUT_ACCESS_ATTEMPT', ip=ip)
            return JsonResponse({'error': {'code': 'LOCKED_OUT', 'message': 'Account temporarily locked'}}, status=423)
        
        if path.startswith('/auth/login'):
            limit, window = 5, 60
        elif path.startswith('/auth/'):
            limit, window = 10, 60
        else:
            limit, window = 100, 60
            
        key = f"rate_limit:{ip}:{path.split('/')[1] if '/' in path else 'root'}"
        current = cache.get(key, 0)
        
        if current >= limit:
            log_security_event('RATE_LIMIT_EXCEEDED', ip=ip, details=f"Path: {path}")
            return JsonResponse({'error': {'code': 'RATE_LIMITED', 'message': 'Too many requests'}}, status=429)
            
        cache.set(key, current + 1, window)
        return None
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

class BruteForceMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.path == '/auth/login/' and request.method == 'POST':
            ip = self.get_client_ip(request)
            attempts_key = f"login_attempts:{ip}"
            attempts = cache.get(attempts_key, 0)
            
            if attempts >= settings.MAX_LOGIN_ATTEMPTS:
                cache.set(f"lockout:{ip}", True, settings.LOCKOUT_DURATION)
                log_security_event('BRUTE_FORCE_LOCKOUT', ip=ip)
                return JsonResponse({'error': {'code': 'LOCKED_OUT', 'message': 'Too many failed attempts'}}, status=423)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')