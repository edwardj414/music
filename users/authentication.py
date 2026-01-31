from rest_framework import authentication, exceptions

from .models import CusUser, BlacklistedAESToken
from .utils import decrypt_user_data


class AESAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        try:
            token = auth_header.split(' ')[1]
            if BlacklistedAESToken.objects.filter(token=token).exists():
                raise exceptions.AuthenticationFailed('Token has been blacklisted (Logged out)')
            user_data = decrypt_user_data(token)
            if not user_data:
                raise exceptions.AuthenticationFailed('Invalid or expired token')
            user = CusUser.objects.get(id=user_data.get('user_id'))
            return (user, None)
        except Exception as e:
            raise exceptions.AuthenticationFailed(f'Auth Error: {str(e)}')