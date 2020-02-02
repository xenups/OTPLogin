import django.contrib.auth.password_validation as validators
from rest_framework import exceptions
from rest_framework import serializers
from rest_framework_jwt.settings import api_settings

from account import models
# User = get_user_model()
from account.models import User

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


# class CustomJWTSerializer(JSONWebTokenSerializer):
#     username_field = 'username'
#
#     def validate(self, attrs):
#         password = attrs.get("password")
#         user_obj = User.objects.filter(username=attrs.get("username")).first()
#         if user_obj is not None:
#             credentials = {
#                 'username': user_obj.username,
#                 'password': password,
#             }
#             if all(credentials.values()):
#                 user = authenticate(**credentials)
#                 if user:
#                     payload = jwt_payload_handler(user)
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


class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.User
        fields = ('phone', 'otp_code')


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = models.User
        fields = ('username', 'first_name', 'last_name', 'phone', 'password', 'email')

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

    def create(self, validated_data):
        user = User.objects.create(**validated_data)
        user.username = validated_data['username']
        user.first_name = validated_data['first_name']
        user.last_name = validated_data['last_name']
        user.phone = validated_data['phone']
        user.set_password(validated_data['password'])
        user.email = validated_data['email']
        user.save()
        return user

    def update(self, instance, validated_data):
        user = validated_data.get('user')
        instance.password = user.get('password')
        instance.email = user.get('email')
        instance.phone = user.get('phone')
        instance.first_name = user.get('first_name')
        instance.last_name = user.get('last_name')
        instance.save()
        return instance
