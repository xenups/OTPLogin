from django.urls import path
from account import views

urlpatterns = [
    path('activation/', views.PhoneActivationView.as_view()),
    path('validation/', views.PhoneValidationView.as_view()),
    path('login/', views.LoginView.as_view()),
    path('register/', views.RegisterUserView.as_view()),
]
