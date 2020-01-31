from rest_framework import serializers, exceptions
import django.contrib.auth.password_validation as validators

from account import models
from rest_framework_jwt.serializers import JSONWebTokenSerializer

from django.contrib.auth import authenticate, get_user_model
from django.utils.translation import ugettext as _
from rest_framework import serializers

from rest_framework_jwt.settings import api_settings

# User = get_user_model()
from account.models import User

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


# class CustomJWTSerializer(JSONWebTokenSerializer):
#     username_field = 'phone'
#
#     def validate(self, attrs):
#         password = attrs.get("password")
#         user_obj = User.objects.filter(phone=attrs.get("phone")).first()
#         if user_obj is not None:
#             credentials = {
#                 'phone': user_obj.phone,
#                 'password': password
#             }
#             if all(credentials.values()):
#                 user = authenticate(**credentials)
#                 if user:
#                     if not user.is_active:
#                         msg = _('User account is disabled.')
#                         raise serializers.ValidationError(msg)
#
#                     payload = jwt_payload_handler(user)
#
#                     return {
#                         'token': jwt_encode_handler(payload),
#                         'user': user
#                     }
#                 else:
#                     msg = _('Unable to log in with provided credentials.')
#                     raise serializers.ValidationError(msg)
#
#         else:
#             msg = _('Account with this email/username does not exists')
#             raise serializers.ValidationError(msg)



class PhoneValidationSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.User
        fields = ('phone',)


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = models.User
        fields = '__all__'

    def validate(self, data):
        password = data.get('password')
        errors = dict()
        try:
            validators.validate_password(password=password, user=models.User)
        except exceptions.ValidationError as e:
            errors['password'] = list(e.messages)

        if errors:
            raise serializers.ValidationError(errors)
        return super(UserSerializer, self).validate(data)
