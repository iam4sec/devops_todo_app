from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.openapi import AutoSchema
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from .views.api import (
    me as _me, lists as _lists, list_detail as _list_detail,
    todos as _todos, todo_detail as _todo_detail, 
    todo_toggle as _todo_toggle, todos_bulk as _todos_bulk
)
from .views.auth import (
    csrf_token as _csrf_token, login as _login,
    refresh as _refresh, logout as _logout
)

# Auth endpoints
@extend_schema(
    summary="Get CSRF Token",
    description="Retrieve CSRF token for authentication",
    responses={200: {"type": "object", "properties": {"csrf_token": {"type": "string"}}}},
    tags=["Authentication"]
)
def csrf_token(request):
    return _csrf_token(request)

@extend_schema(
    summary="User Login",
    description="Authenticate user and set session cookies",
    request={
        "type": "object",
        "properties": {
            "email": {"type": "string", "format": "email"},
            "password": {"type": "string"}
        },
        "required": ["email", "password"]
    },
    responses={
        200: {"type": "object", "properties": {"message": {"type": "string"}}},
        401: {"type": "object", "properties": {"error": {"type": "string"}}}
    },
    tags=["Authentication"]
)
def login(request):
    return _login(request)

@extend_schema(
    summary="Refresh Session",
    description="Refresh user session",
    responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
    tags=["Authentication"]
)
def refresh(request):
    return _refresh(request)

@extend_schema(
    summary="User Logout",
    description="Logout user and clear session",
    responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
    tags=["Authentication"]
)
def logout(request):
    return _logout(request)

# API endpoints
@extend_schema(
    summary="Get Current User",
    description="Get current authenticated user profile",
    responses={
        200: {
            "type": "object",
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "email": {"type": "string", "format": "email"},
                "created_at": {"type": "string", "format": "date-time"}
            }
        },
        401: {"type": "object", "properties": {"error": {"type": "string"}}}
    },
    tags=["User"]
)
def me(request):
    return _me(request)

@extend_schema(
    summary="Lists Management",
    description="Get all lists or create a new list",
    parameters=[
        OpenApiParameter("limit", int, description="Number of items to return (max 50)", default=50),
        OpenApiParameter("cursor", str, description="Pagination cursor"),
        OpenApiParameter("q", str, description="Search query")
    ],
    request={
        "type": "object",
        "properties": {
            "name": {"type": "string", "maxLength": 255},
            "color": {"type": "string", "pattern": "^#[0-9A-Fa-f]{6}$"}
        },
        "required": ["name"]
    },
    responses={
        200: {
            "type": "object",
            "properties": {
                "data": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "format": "uuid"},
                            "name": {"type": "string"},
                            "color": {"type": "string"},
                            "created_at": {"type": "string", "format": "date-time"}
                        }
                    }
                },
                "next_cursor": {"type": "string", "nullable": True}
            }
        },
        201: {
            "type": "object",
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "name": {"type": "string"},
                "color": {"type": "string"},
                "created_at": {"type": "string", "format": "date-time"}
            }
        }
    },
    tags=["Lists"]
)
def lists(request):
    return _lists(request)

@extend_schema(
    summary="List Operations",
    description="Get, update, or delete a specific list",
    request={
        "type": "object",
        "properties": {
            "name": {"type": "string", "maxLength": 255},
            "color": {"type": "string", "pattern": "^#[0-9A-Fa-f]{6}$"}
        }
    },
    responses={
        200: {
            "type": "object",
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "name": {"type": "string"},
                "color": {"type": "string"},
                "created_at": {"type": "string", "format": "date-time"},
                "updated_at": {"type": "string", "format": "date-time"}
            }
        },
        204: {"description": "List deleted successfully"},
        404: {"type": "object", "properties": {"error": {"type": "string"}}}
    },
    tags=["Lists"]
)
def list_detail(request, list_id):
    return _list_detail(request, list_id)

@extend_schema(
    summary="Todos Management",
    description="Get all todos or create a new todo",
    parameters=[
        OpenApiParameter("limit", int, description="Number of items to return (max 50)", default=50),
        OpenApiParameter("cursor", str, description="Pagination cursor"),
        OpenApiParameter("list_id", str, description="Filter by list ID"),
        OpenApiParameter("status", str, description="Filter by status", enum=["open", "doing", "done"]),
        OpenApiParameter("priority", int, description="Filter by priority (1-5)"),
        OpenApiParameter("due_before", str, description="Filter by due date"),
        OpenApiParameter("q", str, description="Search query")
    ],
    request={
        "type": "object",
        "properties": {
            "list_id": {"type": "string", "format": "uuid"},
            "title": {"type": "string", "maxLength": 255},
            "note": {"type": "string", "maxLength": 1000},
            "status": {"type": "string", "enum": ["open", "doing", "done"], "default": "open"},
            "priority": {"type": "integer", "minimum": 1, "maximum": 5, "default": 3},
            "due_date": {"type": "string", "format": "date-time", "nullable": True}
        },
        "required": ["list_id", "title"]
    },
    responses={
        200: {
            "type": "object",
            "properties": {
                "data": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "format": "uuid"},
                            "list_id": {"type": "string", "format": "uuid"},
                            "title": {"type": "string"},
                            "note": {"type": "string"},
                            "status": {"type": "string", "enum": ["open", "doing", "done"]},
                            "priority": {"type": "integer"},
                            "due_date": {"type": "string", "format": "date-time", "nullable": True},
                            "version": {"type": "integer"},
                            "updated_at": {"type": "string", "format": "date-time"}
                        }
                    }
                },
                "next_cursor": {"type": "string", "nullable": True}
            }
        },
        201: {
            "type": "object",
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "list_id": {"type": "string", "format": "uuid"},
                "title": {"type": "string"},
                "note": {"type": "string"},
                "status": {"type": "string"},
                "priority": {"type": "integer"},
                "due_date": {"type": "string", "format": "date-time", "nullable": True},
                "version": {"type": "integer"},
                "updated_at": {"type": "string", "format": "date-time"}
            }
        }
    },
    tags=["Todos"]
)
def todos(request):
    return _todos(request)

@extend_schema(
    summary="Todo Operations",
    description="Get, update, or delete a specific todo",
    request={
        "type": "object",
        "properties": {
            "title": {"type": "string", "maxLength": 255},
            "note": {"type": "string", "maxLength": 1000},
            "status": {"type": "string", "enum": ["open", "doing", "done"]},
            "priority": {"type": "integer", "minimum": 1, "maximum": 5},
            "due_date": {"type": "string", "format": "date-time", "nullable": True}
        }
    },
    responses={
        200: {
            "type": "object",
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "list_id": {"type": "string", "format": "uuid"},
                "title": {"type": "string"},
                "note": {"type": "string"},
                "status": {"type": "string"},
                "priority": {"type": "integer"},
                "due_date": {"type": "string", "format": "date-time", "nullable": True},
                "version": {"type": "integer"},
                "updated_at": {"type": "string", "format": "date-time"}
            }
        },
        204: {"description": "Todo deleted successfully"},
        404: {"type": "object", "properties": {"error": {"type": "string"}}}
    },
    tags=["Todos"]
)
def todo_detail(request, todo_id):
    return _todo_detail(request, todo_id)

@extend_schema(
    summary="Toggle Todo Status",
    description="Toggle todo status between open and done",
    responses={
        200: {
            "type": "object",
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "status": {"type": "string", "enum": ["open", "done"]},
                "version": {"type": "integer"}
            }
        },
        404: {"type": "object", "properties": {"error": {"type": "string"}}}
    },
    tags=["Todos"]
)
def todo_toggle(request, todo_id):
    return _todo_toggle(request, todo_id)

@extend_schema(
    summary="Bulk Todo Operations",
    description="Perform bulk operations on todos (create, update, delete)",
    request={
        "type": "object",
        "properties": {
            "operations": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string", "enum": ["create"]},
                                "list_id": {"type": "string", "format": "uuid"},
                                "title": {"type": "string"},
                                "note": {"type": "string"},
                                "status": {"type": "string", "enum": ["open", "doing", "done"]},
                                "priority": {"type": "integer", "minimum": 1, "maximum": 5}
                            },
                            "required": ["type", "list_id", "title"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string", "enum": ["update"]},
                                "id": {"type": "string", "format": "uuid"},
                                "title": {"type": "string"},
                                "note": {"type": "string"},
                                "status": {"type": "string", "enum": ["open", "doing", "done"]},
                                "priority": {"type": "integer", "minimum": 1, "maximum": 5}
                            },
                            "required": ["type", "id"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string", "enum": ["delete"]},
                                "id": {"type": "string", "format": "uuid"}
                            },
                            "required": ["type", "id"]
                        }
                    ]
                }
            }
        },
        "required": ["operations"]
    },
    responses={
        200: {
            "type": "object",
            "properties": {
                "results": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "enum": ["created", "updated", "deleted"]},
                            "id": {"type": "string", "format": "uuid"}
                        }
                    }
                }
            }
        }
    },
    tags=["Todos"]
)
def todos_bulk(request):
    return _todos_bulk(request)