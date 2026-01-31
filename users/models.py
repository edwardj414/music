from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import AbstractUser
from django.db import models

class CusUser(AbstractUser):
    username = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=128)
    first_name = models.CharField(max_length=128, null=True, blank=True,default='')
    last_name = models.CharField(max_length=128, null=True, blank=True,default='')
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)
    code = models.CharField(max_length=10, blank=True, null=True)
    is_host = models.BooleanField(default=False)

    def __str__(self):
        return self.username

class OTP(models.Model):
    user = models.ForeignKey(CusUser, on_delete=models.CASCADE, related_name='otps')
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=5)
        super().save(*args, **kwargs)

    def is_valid(self):
        return timezone.now() < self.expires_at

    def __str__(self):
        return f"{self.code} for {self.user.username}"


class BlacklistedAESToken(models.Model):
    token = models.TextField(unique=True)
    blacklisted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Blacklisted at {self.blacklisted_at}"