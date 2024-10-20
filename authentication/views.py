from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import login, logout
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from .tokens import account_activation_token
from .forms import CaptchaTestForm
import json


class UserTable():
    user_name = ""
    is_admin = False
    def __init__(self, name, isAdmin):
        self.user_name = name
        self.is_admin = isAdmin

    def to_string(self):
        print("user name" + self.user_name + "admin" + str(self.is_admin))    

# Create your views here.
def home(request):
    if request.user.is_authenticated:
        logout(request)
    return redirect('signin')

def mainpage(request):
    
    user_list = []
    for object in User.objects.all():
        user_list.append(UserTable(object.username, object.is_superuser))

    context = {"user":user_list}
    if request.user.is_authenticated:
        return render(request, "authentication/mainpage.html", context)
    return redirect('signin')

def signin(request):
    if request.method == 'POST':
        form=CaptchaTestForm(request.POST)
        if(form.is_valid()):
            username = request.POST['username']
            pass1 = request.POST['pass1']
            try:
                user  = get_user(username)
                if user is not None:
                    pwd_valid = check_password(pass1, user.password)
                    if pwd_valid:
                        login(request, user)
                        return redirect("mainpage")
                    else:
                        messages.error(request, "Invalid password!! Please enter a valid password")
                else:
                    messages.error(request, "Invalid username!! Please enter a valid user name") 
            except User.DoesNotExist:
                    return None
        else:
            messages.error(request, "Invalid captcha")
    form=CaptchaTestForm()
    context = {"form":form}
    return render(request, "authentication/signin.html", context)

def signout(request):
    logout(request)
    messages.success(request, "Logged Out Successfully!!")
    return redirect('signin')

def get_user(username):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            return None
        
def changePassword(request):
    if request.method == "POST":
        print(request.user.is_authenticated)
        if request.user.is_authenticated:
            print("User autheticated")
            print(request.user.email)
            pass1 = request.POST['pass1']
            pass2 = request.POST['pass2']
            if pass1 != pass2:
                messages.error(request, "Passwords didn't matched!!")
                return redirect('changePassword')
            if User.objects.filter(email=request.user.email).exists():
                if request.user is not None:
                    request.user.set_password(pass1)
                    request.user.save()
                    logout(request)
                    return redirect('signin')
            else:
                messages.error(request, "Change Password failed!!")
                logout(request)
                return redirect('signin')
        else:
            messages.error(request, "User authentication failed!!")
            logout(request)
            return redirect('signin')
    return render(request, "authentication/change_password.html")

def adduser(request):
    if request.method == "POST":
        username = request.POST['username']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']
        isadmin = request.POST['isadmin']
        if User.objects.filter(username=username):
            messages.error(request, "Username already exist! Please try some other username.")
            return redirect('adduser')
        
        if len(username)>20:
            messages.error(request, "Username must be under 20 charcters!!")
            return redirect('adduser')
        
        if pass1 != pass2:
            messages.error(request, "Passwords didn't matched!!")
            return redirect('adduser')
        
        myuser = User.objects.create_user(username=username)
        myuser.is_superuser = isadmin
        myuser.set_password(pass1)
        myuser.save()
        return redirect("mainpage")
    return render(request, "authentication/adduser.html")


def deleteuser(request):
    if request.method == "POST":
        username = request.POST['username']
        try:
            u = User.objects.get(username = username)
            u.delete()
            return redirect("mainpage")           

        except User.DoesNotExist:
            messages.error(request, "User doesnot exist")    
            return redirect("deleteuser")
    return render(request, "authentication/deleteuser.html")


def edituser(request):
    if request.method == "POST":
        username = request.POST['username']
        pass1 = request.POST['pass1']
        isadmin = request.POST['isadmin']

        if User.objects.filter(username=username):
            myuser = User.objects.get(username=username)
            if myuser.check_password(pass1):
                myuser.is_superuser = isadmin
                myuser.save()
                return redirect("mainpage")
            else:
                messages.error(request, "Entered wrong password")
                return redirect('edituser')
        else:
            messages.error(request, "Username does not exist")
            return redirect('edituser')
    return render(request, "authentication/edituser.html")


        
