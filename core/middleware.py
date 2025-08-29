import logging
from django.http import JsonResponse
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

def get_ip(request):
    """Extract client IP with proper proxy handling"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class OptimizedMiddleware(MiddlewareMixin):
    """Optimized middleware with better rate limiting and security headers"""
    
    def process_request(self, request):
        # Enhanced rate limiting with different limits per endpoint type
        ip = get_ip(request)
        path = request.path.lower()
        
        # Determine rate limit based on endpoint
        if 'login' in path:
            limit, window = 5, 300  # 5 attempts per 5 minutes
            key = f"rate:login:{ip}"
        elif 'auth' in path:
            limit, window = 20, 60  # 20 requests per minute
            key = f"rate:auth:{ip}"
        elif any(write_path in path for write_path in ['create', 'update', 'delete', 'toggle', 'bulk']):
            limit, window = 60, 60  # 60 write operations per minute
            key = f"rate:write:{ip}"
        else:
            limit, window = 200, 60  # 200 read requests per minute
            key = f"rate:read:{ip}"
        
        # Check rate limit
        current_count = cache.get(key, 0)
        if current_count >= limit:
            logger.warning(f"Rate limit exceeded for IP {ip} on path {path}")
            return JsonResponse({
                'error': 'Rate limit exceeded',
                'retry_after': window
            }, status=429)
        
        # Increment counter
        cache.set(key, current_count + 1, window)
        return None
    
    def process_response(self, request, response):
        # Enhanced security headers
        security_headers = {
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
            'X-XSS-Protection': '1; mode=block',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        }
        
        for header, value in security_headers.items():
            response[header] = value
        
        # Add CORS headers for API endpoints
        if request.path.startswith('/api/') or request.path.startswith('/auth/'):
            response['Access-Control-Allow-Credentials'] = 'true'
            response['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRFToken'
            response['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, DELETE, OPTIONS'
        
        return response