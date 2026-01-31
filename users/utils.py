import random
import string
import base64
import json
from django.utils import timezone
from datetime import timedelta
from cryptography.fernet import Fernet
from django.conf import settings

cipher = Fernet(settings.AES_KEY.encode())

def generte_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def encrypt_user_data(data_dict, minutes=60):
    expire_time = timezone.now() + timedelta(minutes=minutes)
    data_dict['expire_time'] = expire_time.timestamp()
    json_text = json.dumps(data_dict)
    encrypted_text = cipher.encrypt(json_text.encode())
    return base64.urlsafe_b64encode(encrypted_text).decode()


def decrypt_user_data(token):
    try:
        decoded_text = base64.urlsafe_b64decode(token.encode())
        decrypted_text = cipher.decrypt(decoded_text)
        data = json.loads(decrypted_text.decode())
        if timezone.now().timestamp() > data.get('expire_time', 0):
            return None
        return data
    except Exception:
        return None