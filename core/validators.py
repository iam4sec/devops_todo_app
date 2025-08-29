import re
import html
import logging
from django.core.exceptions import ValidationError
from django.utils.html import strip_tags

logger = logging.getLogger('security')

class InputValidator:
    @staticmethod
    def validate_email(email):
        if not email or len(email) > 254:
            raise ValidationError("Invalid email format")
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            raise ValidationError("Invalid email format")
        return email.lower().strip()
    
    @staticmethod
    def validate_password(password):
        if not password or len(password) < 8:
            raise ValidationError("Password must be at least 8 characters")
        if len(password) > 128:
            raise ValidationError("Password too long")
        if not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain uppercase letter")
        if not re.search(r'[a-z]', password):
            raise ValidationError("Password must contain lowercase letter")
        if not re.search(r'\d', password):
            raise ValidationError("Password must contain number")
        return password
    
    @staticmethod
    def sanitize_text(text, max_length=1000):
        if not text:
            return ""
        text = str(text)[:max_length]
        text = strip_tags(text)
        text = html.escape(text)
        return text.strip()
    
    @staticmethod
    def validate_uuid(uuid_str):
        pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if not re.match(pattern, str(uuid_str).lower()):
            raise ValidationError("Invalid UUID format")
        return str(uuid_str).lower()

def log_security_event(event_type, user_id=None, ip=None, details=None):
    logger.warning(f"{event_type} - User: {user_id} - IP: {ip} - Details: {details}")