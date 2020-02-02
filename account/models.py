from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.core.validators import RegexValidator
from django.db import models

from account.managers import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField('username', max_length=30, blank=True, unique=True)
    email = models.EmailField('email address', unique=True)
    first_name = models.CharField('first name', max_length=30, blank=True)
    last_name = models.CharField('last name', max_length=30, blank=True)
    date_joined = models.DateTimeField('date joined', auto_now_add=True, editable=True)
    is_active = models.BooleanField('active', default=True)
    is_staff = models.BooleanField('staff status', default=True, )
    otp_code = models.CharField(max_length=9, null=True, blank=True)
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be entered in the format: "
                                                                   "'+999999999'. Up to 15 digits allowed.")
    phone = models.CharField('phone number', validators=[phone_regex], max_length=15,
                             unique=True)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True, editable=True)
    USERNAME_FIELD = 'username'
    objects = UserManager()

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'
