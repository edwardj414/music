import json
from rest_framework.renderers import JSONRenderer
from .utils import cipher # Uses the Fernet suite you created earlier


class AESEncryptionRenderer(JSONRenderer):
    """
    Custom renderer that encrypts the final JSON response body using AES.
    """
    charset = 'utf-8'
    def render(self, data, accepted_media_type=None, renderer_context=None):
        # 1. Convert data to standard JSON string
        json_data = super().render(data, accepted_media_type, renderer_context)

        # 2. Encrypt the entire JSON body
        encrypted_data = cipher.encrypt(json_data)

        # 3. Return as a dictionary so the client receives a single encrypted field
        # or return the raw encrypted string
        return json.dumps(encrypted_data.decode())