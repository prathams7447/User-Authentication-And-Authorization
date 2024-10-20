from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('captcha', include('captcha.urls')),
    path('signin', views.signin, name='signin'),
    path('signout', views.signout, name='signout'),
    path('changePassword', views.changePassword, name='changePassword'),
    path('adduser', views.adduser, name='adduser'),
    path('mainpage', views.mainpage, name='mainpage'),
    path('deleteuser', views.deleteuser, name='deleteuser'),
    path('edituser', views.edituser, name='edituser'),
]
