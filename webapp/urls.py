from django.urls import path
from . import views
from django.views.generic import TemplateView



urlpatterns = [
    #path('', views.index, name = 'index'),
    path('', TemplateView.as_view(template_name='webapp/main.html'), name ='inicio'),
    path('cifrador/', views.CifradorView.as_view(), name='cifrador'),
    path('descifrador/', views.DescifradorView.as_view(), name = 'descifrador'),
    path('firmador/', views.FirmadorView.as_view(), name = 'firmador'),
    path('verificador/', views.VerificadorView.as_view(), name = 'verificador'),
]
