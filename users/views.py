from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password, make_password
from django.forms.models import model_to_dict
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken


from .serializers import SignupSerializer
from .serializers import CheckPassword

class SignUp(APIView):
    permission_classes = (AllowAny,)
    @staticmethod
    def post(request):
        data = request.data
        serializer = SignupSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
            user_data = model_to_dict(user, exclude=["password"])
            return Response({"message":"User Created","data":user_data}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Login(APIView):
    permission_classes = (AllowAny,)
    def post(self, request):
        data = request.data
        username = data.get('username')
        password = data.get('password')
        if not all([username,password]):
            return Response("Username and Password are required", status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(request, username=username, password=password)
        print(password)
        print(user)
        if not user:
            return Response("Invalid Credentials", status=status.HTTP_401_UNAUTHORIZED)
        refresh = RefreshToken.for_user(user)
        us = model_to_dict(user, exclude=['password'])
        return Response({"message": "Login Successful",
                         "data": us, "Access_Token": str(refresh.access_token), "Refresh_token":str(refresh)},
                            status=status.HTTP_200_OK)

class Logout(APIView):
    permission_classes = (IsAuthenticated,)
    @staticmethod
    def post(request):
        refresh = RefreshToken.for_user(request.user)
        if not refresh:
            return Response("Refresh token is required", status=status.HTTP_400_BAD_REQUEST)
        token = RefreshToken(refresh)
        token.blacklist()
        return Response("Logout Successful", status=status.HTTP_200_OK)

class ChangePassword(APIView):
    permission_classes = (IsAuthenticated,)
    @staticmethod
    def post(request):
        try:
            data = request.data
            old_password = data.get('old_password')
            new_password = data.get('new_password')
            user = request.user
            if not check_password(old_password, user.password):
                return Response("Password Incorrect", status=status.HTTP_400_BAD_REQUEST)
            if old_password == new_password:
                return Response("New Password cannot be same as Old Password", status=status.HTTP_400_BAD_REQUEST)
            if CheckPassword.validate_pass(new_password):
                user.set_password(new_password)
                user.save()
                return Response("Password Changed Successful", status=status.HTTP_200_OK)
            else:
                return Response("The password must be Alphanumeric with Upper, Lower and Special Characters",
                                status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"message": "Something Went Wrong","data":str(e)}, status=status.HTTP_400_BAD_REQUEST)

class DeleteUser(APIView):
    permission_classes = (IsAuthenticated,)
    @staticmethod
    def post(request):
        try:
            request.user.delete()
            return Response("User Deleted Successful", status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message":"Something Went Wrong","data": str(e)}, status=status.HTTP_400_BAD_REQUEST)


