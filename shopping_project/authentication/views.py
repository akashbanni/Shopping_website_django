from django.shortcuts import render,redirect,HttpResponse
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site  
from django.views.generic import View
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from .utils import TokenGenerator,generate_token
from django.utils.encoding import force_bytes,DjangoUnicodeDecodeError
from django.utils.encoding import force_str
from django.core.mail import EmailMessage
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.conf import settings
from django.contrib.auth import authenticate,login,logout



# Create your views here.
def signup(request):
    if request.method == 'POST':
        name = request.POST["name"]
        Email = request.POST["email"]
        password = request.POST["pass1"]
        confirm_pwd = request.POST["pass2"]
        if password != confirm_pwd:
            messages.warning(request,"Password and confirm password not matched")
            #return HttpResponse("Password and confirm password not matched")
            return render(request,"signup.html")
        try:
            if User.objects.get(username=Email):
                messages.warning(request,"{0} already exsits".format(Email))
                #return HttpResponse("Username already exists")

                return render(request,"signup.html")
        except Exception as identifier:
            pass
        user = User.objects.create_user(Email,Email,password,first_name=name)
        user.is_active=False
        user.save()
        email_subject = "ACTIVATE YOU ACCOUNT"
        current_site = get_current_site(request)  
        message = render_to_string('activate.html',{
            'user':User,
            'domain':current_site.domain,
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token':generate_token.make_token(user)
            })
        print(urlsafe_base64_encode(force_bytes(user.pk)))
        email_message = EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[Email])
        email_message.send()

        messages.success(request,"Activate Your Account by clicking the link in your gmail")
        return redirect('/auth/login/')
     

        #return HttpResponse("User Created",Email)
    
    return render(request,'signup.html')

class ActivateAccountView(View):
    def activate(request,uidb64,token):
        try:
            uid=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
            print(uid)
        except Exception as identifier:
            user=None
        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            print(user,token)
            messages.info(request,"Account Activated Successfully")
            return redirect('/auth/login')
        return render(request,'activatefail.html')
    


def login_account(request):
    if request.method=="POST":

        username=request.POST['email']
        userpassword=request.POST['pass1']
        myuser=authenticate(username=username,password=userpassword)

        if myuser is not None:
            login(request,myuser)
            messages.success(request,"Login Success")
            return redirect('/')

        else:
            messages.error(request,"Invalid Credentials")
            return redirect('/auth/login')
    return render(request,'login.html')




def logout_account(request):
    logout(request)
    messages.info(request,"Logout Success")
    return redirect('/auth/login')


class RequestResetEmailView(View):
    def get(self,request):
        return render(request,'resetpassword.html')
    def post(self,request):
        email=request.POST['email']
        user=User.objects.filter(email=email)

        if user.exists():
            current_site = get_current_site(request)
            email_subject = '[RESET YOUR PASSWORD]'
            message = render_to_string('setnewpassword.html',{
                'domain':current_site.domain,
                'uid':urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token':PasswordResetTokenGenerator().make_token(user[0])
                })
            email_message = EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email])
            email_message.send()

            messages.success(request,"Create Your Account Password by using link in your gmail")
            return render(request,'resetpassword.html')
        

class SetNewPasswordView(View):
    def get(self,request,uidb64,token):
        context={
            'uidb64':uidb64,
            'token':token
        }
        try:
            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user,token):
                messages.warning(request,"Password reset link is invalid")
                return render(request, 'resetpassword.html')
        except DjangoUnicodeDecodeError as identifier:
            pass
        return render (request , "setpassword.html",context )
    
    def post(self,request,uidb64,token):
        context={
            'uidb64':uidb64,
            'token':token
        }
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']
        if password != confirm_password:
            messages.warning(request,"password is not matched")
            return render(request,'setpassword.html')
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            print(password)
            messages.success(request,"Password reset success")
            return redirect('/auth/login')
        except DjangoUnicodeDecodeError as e:
            messages.error(request,"Somthing went wrong")
        return render(request,"/setpassword.html",context)
        #return render(request,"/setpassword.html",context)
        
        