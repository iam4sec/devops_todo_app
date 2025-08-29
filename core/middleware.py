from django.http import JsonResponse
from django.core.cache import cache

def get_ip(request):
    return request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0] or request.META.get('REMOTE_ADDR')

class OptimizedMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Rate limiting
        ip = get_ip(request)
        key = f"rate:{ip}:{request.path.split('/')[1] if '/' in request.path else 'root'}"
        limit = 5 if 'login' in request.path else 100
        
        if cache.get(key, 0) >= limit:
            return JsonResponse({'error': 'Rate limited'}, status=429)
        cache.set(key, cache.get(key, 0) + 1, 60)
        
        response = self.get_response(request)
        
        # Security headers
        response['X-Frame-Options'] = 'DENY'
        response['X-Content-Type-Options'] = 'nosniff'
        response['Referrer-Policy'] = 'no-referrer'
        return response