import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, username=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    email = models.EmailField(unique=True, db_index=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    objects = UserManager()
    
    class Meta:
        indexes = [models.Index(fields=['email'])]

class Session(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, db_index=True)
    ip = models.GenericIPAddressField(db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'expires_at']),
            models.Index(fields=['ip', 'expires_at'])
        ]

class List(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, db_index=True)
    name = models.CharField(max_length=255, db_index=True)
    color = models.CharField(max_length=7, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['user', 'name'])
        ]

class Todo(models.Model):
    STATUS_CHOICES = [('open', 'Open'), ('doing', 'Doing'), ('done', 'Done')]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    list = models.ForeignKey(List, on_delete=models.CASCADE, db_index=True, related_name='todos')
    title = models.CharField(max_length=255, db_index=True)
    note = models.TextField(blank=True)
    status = models.CharField(max_length=5, choices=STATUS_CHOICES, default='open', db_index=True)
    priority = models.IntegerField(default=3, db_index=True)
    due_date = models.DateField(null=True, blank=True, db_index=True)
    version = models.IntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['list', 'status']),
            models.Index(fields=['list', 'priority']),
            models.Index(fields=['list', 'due_date']),
            models.Index(fields=['list', 'updated_at'])
        ]