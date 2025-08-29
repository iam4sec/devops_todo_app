from django.urls import path, include
from django.views.generic import TemplateView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path('auth/', include('core.urls.swagger_auth')),
    path('', include('core.urls.swagger_api')),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('docs/', TemplateView.as_view(template_name='swagger/index.html'), name='docs-static'),
]