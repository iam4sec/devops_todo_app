import time
from django.http import JsonResponse
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin

class SecurityMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        response['X-Frame-Options'] = 'DENY'
        response['X-Content-Type-Options'] = 'nosniff'
        response['Referrer-Policy'] = 'no-referrer'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return response

class RateLimitMiddleware(MiddlewareMixin):
    def process_request(self, request):
        ip = self.get_client_ip(request)
        path = request.path
        
        if path.startswith('/auth/login'):
            limit, window = 5, 60
        elif path.startswith('/auth/'):
            limit, window = 10, 60
        else:
            limit, window = 100, 60
            
        key = f"rate_limit:{ip}:{path.split('/')[1] if '/' in path else 'root'}"
        current = cache.get(key, 0)
        
        if current >= limit:
            return JsonResponse({'error': {'code': 'RATE_LIMITED', 'message': 'Too many requests'}}, status=429)
            
        cache.set(key, current + 1, window)
        return None
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')