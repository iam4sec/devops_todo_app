from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.utils.html import strip_tags
from rest_framework import serializers
import html
import re

class BaseSerializer:
    def __init__(self, data):
        self.data = data
        self.errors = {}
    
    def is_valid(self):
        return len(self.errors) == 0
    
    def validate_field(self, field, value, required=False, max_len=None, pattern=None):
        if required and not value:
            self.errors[field] = f"{field} is required"
            return None
        
        if value and max_len and len(str(value)) > max_len:
            self.errors[field] = f"{field} exceeds maximum length"
            return None
        
        if value and pattern and not re.match(pattern, str(value)):
            self.errors[field] = f"Invalid {field} format"
            return None
        
        if isinstance(value, str):
            return html.escape(strip_tags(value.strip()))
        return value

class LoginSerializer(BaseSerializer):
    def validate(self):
        email = self.validate_field('email', self.data.get('email'), 
                                  required=True, max_len=254, 
                                  pattern=r'^[^@]+@[^@]+\.[^@]+$')
        password = self.validate_field('password', self.data.get('password'), 
                                     required=True, max_len=128)
        
        if self.is_valid():
            user = authenticate(username=email.lower(), password=password)
            if not user:
                self.errors['credentials'] = 'Invalid credentials'
                return None
            return {'user': user, 'email': email}
        return None

class ListSerializer(BaseSerializer):
    def validate(self):
        name = self.validate_field('name', self.data.get('name'), 
                                 required=True, max_len=255)
        color = self.validate_field('color', self.data.get('color'), 
                                  max_len=7, pattern=r'^#[0-9A-Fa-f]{6}$')
        
        if self.is_valid():
            return {'name': name, 'color': color}
        return None

class TodoSerializer(BaseSerializer):
    def validate(self):
        list_id = self.validate_field('list_id', self.data.get('list_id'), 
                                    required=True, max_len=36, 
                                    pattern=r'^[0-9a-f-]{36}$')
        title = self.validate_field('title', self.data.get('title'), 
                                  required=True, max_len=255)
        status = self.validate_field('status', self.data.get('status'), 
                                   max_len=5, pattern=r'^(open|doing|done)$')
        priority = self.validate_field('priority', self.data.get('priority'), 
                                     pattern=r'^[1-5]$')
        
        if self.is_valid():
            return {
                'list_id': list_id,
                'title': title,
                'status': status or 'open',
                'priority': int(priority) if priority else 3
            }
        return None

# DRF Serializers for schema generation
class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(help_text="User email address")
    password = serializers.CharField(min_length=8, help_text="User password")
    password_confirm = serializers.CharField(help_text="Password confirmation")

class LoginRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(help_text="User email address")
    password = serializers.CharField(help_text="User password")

class ListCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255, help_text="List name")
    color = serializers.RegexField(regex=r'^#[0-9A-Fa-f]{6}$', required=False, help_text="Hex color code")

class TodoCreateSerializer(serializers.Serializer):
    list_id = serializers.UUIDField(help_text="List ID")
    title = serializers.CharField(max_length=255, help_text="Todo title")
    status = serializers.ChoiceField(choices=['open', 'doing', 'done'], default='open', required=False)
    priority = serializers.IntegerField(min_value=1, max_value=5, default=3, required=False)

class TodoUpdateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=255, required=False, help_text="Todo title")
    status = serializers.ChoiceField(choices=['open', 'doing', 'done'], required=False)
    priority = serializers.IntegerField(min_value=1, max_value=5, required=False)

class BulkCreateOperationSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=['create'])
    list_id = serializers.UUIDField()
    title = serializers.CharField(max_length=255)

class BulkDeleteOperationSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=['delete'])
    id = serializers.UUIDField()

class TodosBulkSerializer(serializers.Serializer):
    operations = serializers.ListField(
        child=serializers.JSONField(),
        max_length=100,
        help_text="Array of operations to perform"
    )