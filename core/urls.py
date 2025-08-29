from django.urls import path
from . import views

urlpatterns = [
    # Root
    path('', views.api_info, name='api_info'),
    
    # Auth - Class-based views
    path('auth/register/', views.RegisterView.as_view(), name='register'),
    path('auth/csrf/', views.CSRFTokenView.as_view(), name='csrf'),
    path('auth/login/', views.LoginView.as_view(), name='login'),
    path('auth/refresh/', views.RefreshView.as_view(), name='refresh'),
    path('auth/logout/', views.LogoutView.as_view(), name='logout'),
    
    # User - Class-based views
    path('me/', views.MeView.as_view(), name='me'),
    
    # Lists - RESTful endpoints
    path('lists/', views.ListsView.as_view(), name='lists'),  # GET, POST
    path('lists/<uuid:list_id>/', views.ListDetailView.as_view(), name='list_detail'),  # GET, PUT, DELETE
    
    # Todos - RESTful endpoints
    path('todos/', views.TodosView.as_view(), name='todos'),  # GET, POST
    path('todos/<uuid:todo_id>/', views.TodoDetailView.as_view(), name='todo_detail'),  # GET, PUT, DELETE
    path('todos/<uuid:todo_id>/toggle/', views.TodoToggleView.as_view(), name='todo_toggle'),  # POST
    path('todos/bulk/', views.TodosBulkView.as_view(), name='todos_bulk'),  # POST
]