import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    email = models.EmailField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

class Session(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip = models.GenericIPAddressField()
    ua = models.TextField()
    expires_at = models.DateTimeField()
    rotated_from = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

class List(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    color = models.CharField(max_length=7, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Todo(models.Model):
    STATUS_CHOICES = [('open', 'Open'), ('doing', 'Doing'), ('done', 'Done')]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    list = models.ForeignKey(List, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    note = models.TextField(blank=True)
    status = models.CharField(max_length=5, choices=STATUS_CHOICES, default='open')
    priority = models.IntegerField(default=3)
    due_date = models.DateField(null=True, blank=True)
    version = models.IntegerField(default=1)
    updated_at = models.DateTimeField(auto_now=True)

class IdempotencyKey(models.Model):
    key = models.CharField(max_length=255, unique=True)
    response_data = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)