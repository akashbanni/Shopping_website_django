from django.urls import path
from authentication import views

urlpatterns = [
    path('signup/',views.signup, name="signup"),
    path('login/',views.login_account, name="login"),
    path('logout/',views.logout_account, name="logout"),
    path('activate/<uidb64>/<token>/',views.ActivateAccountView.activate,name='activate'),
    path('resetpassword/',views.RequestResetEmailView.as_view(),name='resetpassword'),
    path('setpassword/<uidb64>/<token>/',views.SetNewPasswordView.as_view(),name='setpassword'),
    #path('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',views.ActivateAccountView.as_view(), name='activate'),
]