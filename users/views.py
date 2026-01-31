from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password, make_password
from django.forms.models import model_to_dict
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from sqlalchemy.sql.functions import user

from .models import CusUser, OTP, BlacklistedAESToken
from .serializers import SignupSerializer
from .serializers import CheckPassword
from .utils import generte_otp, encrypt_user_data,decrypt_user_data


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
        if not user:
            return Response("Invalid Credentials", status=status.HTTP_401_UNAUTHORIZED)
        payload = {
            "user_id": user.id,
            "username": user.username}
        aes_token = encrypt_user_data(payload, minutes=60)
        us = model_to_dict(user, exclude=["password"])
        return Response({"message": "Login Successful",
                         "data": us, "Token": aes_token },
                            status=status.HTTP_200_OK)

class Logout(APIView):
    permission_classes = (IsAuthenticated,)
    @staticmethod
    def post(request):
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            # Add the token to our deny list
            BlacklistedAESToken.objects.get_or_create(token=token)
            return Response({"detail": "Logout Successful"}, status=status.HTTP_200_OK)

        return Response({"detail": "Token required"}, status=status.HTTP_400_BAD_REQUEST)


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

class GenerateOTP(APIView):
    permission_classes = (AllowAny,)
    def post(self, request):
        username = request.data.get('username')
        try:
            user = CusUser.objects.get(username=username)
            if not user:
                return Response("User not found", status=status.HTTP_400_BAD_REQUEST)
            OTP.objects.filter(user=user).delete()
            otp = generte_otp()
            OTP.objects.create(user=user, code=otp)
            return Response({"message": "OTP Created and will expire in 5 minutes",
                             "code" :otp},
                              status=status.HTTP_201_CREATED)
        except CusUser.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)


class OTPVerify(APIView):
    permission_classes = (AllowAny,)
    def post(self, request):
        try:
            data = request.data
            otp = data.get('otp')
            phone_number = data.get('phone_number')
            try:
                user = CusUser.objects.get(phone_number=phone_number)
            except CusUser.DoesNotExist:
                return Response("User not found", status=status.HTTP_400_BAD_REQUEST)
            db_otp = OTP.objects.filter(user=user).last()
            if not db_otp:
                return Response("OTP not found for this user", status=status.HTTP_400_BAD_REQUEST)
            if timezone.now() > db_otp.expires_at:
                db_otp.delete()
                return Response("OTP Expired", status=status.HTTP_400_BAD_REQUEST)
            if str(otp) == db_otp.code:
                db_otp.delete()
                return Response("OTP Verified", status=status.HTTP_200_OK)
            else:
                return Response("OTP not matched", status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"message":"Something Went Wrong","data":str(e)}, status=status.HTTP_400_BAD_REQUEST)


class DecryptData(APIView):
    permission_classes = (AllowAny,)
    def post(self, request):
        from cryptography.fernet import Fernet
        import json

        # Your provided secret key
        secret_key = "_fLzsvvDl4-iCPA3fALvgBh7u0Yzm69WfTQH0cOoCNk="

        # Your provided encrypted data
        try:
            # Initialize the cipher with the secret key
            encrypted_data = request.data.get('encrypted_data')
            cipher_suite = Fernet(secret_key)

            # Decrypt the data
            decoded_bytes = cipher_suite.decrypt(encrypted_data.encode())

            # Parse the JSON payload
            decoded_payload = json.loads(decoded_bytes.decode())

            print("Decoded Data:")
            print(json.dumps(decoded_payload, indent=4))
            return Response({"data": decoded_payload}, status=status.HTTP_200_OK)
        except Exception as e:
            print(f"Decoding failed: {str(e)}")