import json
import uuid
from datetime import datetime, timedelta
from django.http import JsonResponse
from django.core.cache import cache
from django.utils import timezone
from .models import Session, IdempotencyKey

def json_response(data, status=200):
    return JsonResponse(data, status=status)

def error_response(code, message, details=None, status=400):
    error_data = {
        'error': {
            'code': code,
            'message': message,
            'request_id': str(uuid.uuid4())
        }
    }
    if details:
        error_data['error']['details'] = details
    return JsonResponse(error_data, status=status)

def create_session(user, request):
    expires_at = timezone.now() + timedelta(minutes=15)
    session = Session.objects.create(
        user=user,
        ip=request.META.get('REMOTE_ADDR'),
        ua=request.META.get('HTTP_USER_AGENT', ''),
        expires_at=expires_at
    )
    return session

def check_idempotency(key):
    try:
        idem = IdempotencyKey.objects.get(key=key)
        return idem.response_data
    except IdempotencyKey.DoesNotExist:
        return None

def save_idempotency(key, response_data):
    IdempotencyKey.objects.create(key=key, response_data=response_data)