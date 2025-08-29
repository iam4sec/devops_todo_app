from rest_framework.response import Response
from rest_framework import status

def api_response(message=None, code=None, data=None, path=None, status_code=status.HTTP_200_OK):
    """Standardized API response format"""
    response_data = {
        'message': message,
        'code': code,
        'path': path,
        'data': data
    }
    return Response(response_data, status=status_code)

def success_response(message, code, data=None, path=None):
    """Success response helper"""
    return api_response(message, code, data, path, status.HTTP_200_OK)

def created_response(message, code, data=None, path=None):
    """Created response helper"""
    return api_response(message, code, data, path, status.HTTP_201_CREATED)

def error_response(message, code, data=None, path=None, status_code=status.HTTP_400_BAD_REQUEST):
    """Error response helper"""
    return api_response(message, code, data, path, status_code)