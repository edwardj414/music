from django.urls import path

from .views import *

urlpatterns = [
    path('decrypt/', DecryptData.as_view(), name='decrypt'),
    path('signup/', SignUp.as_view(), name='signup'),
    path('login/', Login.as_view(), name='login'),
    path('logout/', Logout.as_view(), name='logout'),
    path('change-password/', ChangePassword.as_view(), name='change-password'),
    path('delete-user/', DeleteUser.as_view(), name='delete-user'),
    path('generate-otp/', GenerateOTP.as_view(), name='generate-otp'),
    path('verify-otp/', OTPVerify.as_view(), name='verify-otp'),
]