import json

from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.exceptions import NotFound
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from account import models, serializers
from account.util import generate_otp_code, get_time_diff, set_cache_multiple_value, get_cache_value
from django.core.cache import cache


class PhoneActivationView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.PhoneValidationSerializer

    @staticmethod
    def post(request, *args, **kwargs):
        otp_code = generate_otp_code()
        phone = str(request.data['phone']).strip()
        otp_cache_status = set_cache_multiple_value(phone, otp_code, 'activation_token', ttl=60)
        # send message
        if otp_cache_status:
            return Response(({'otp': otp_code}), status=status.HTTP_201_CREATED)
        raise NotFound('Phone number not found', code=status.HTTP_400_BAD_REQUEST)


class PhoneValidationView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.PhoneValidationSerializer

    @staticmethod
    def post(request, *args, **kwargs):
        validated_token = generate_otp_code()
        phone = str(request.data['phone']).strip()
        user_activation_token = str(request.data['activation_token']).strip()

        activation_token = get_cache_value(phone, 'activation_token')
        if activation_token and activation_token == user_activation_token:
            set_cache_multiple_value(phone, validated_token, 'validated_token', ttl=3000)
            return Response(({'validated_token': validated_token}), status=status.HTTP_201_CREATED)
        raise NotFound('activation code expired', code=status.HTTP_400_BAD_REQUEST)


class RegisterUserView(generics.ListCreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.UserSerializer
    queryset = models.User.objects.all()

    def create(self, request, *args, **kwargs):
        phone = str(request.data['phone']).strip()
        user_token = str(request.data['validated_token']).strip()
        validated_token = get_cache_value(phone, 'validated_token')
        if validated_token and str(validated_token) == user_token:
            response = super(RegisterUserView, self).create(request, *args, **kwargs)
            response.status = status.HTTP_200_OK
            return response
        raise NotFound('registration time expired', code=status.HTTP_204_NO_CONTENT)


class LoginView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.LoginSerializer

    @staticmethod
    def post(request, *args, **kwargs):
        phone = str(request.data['phone']).strip()
        otp_code = str(request.data['otp_code']).strip()
        user = models.User.objects.filter(phone=phone, otp_code=otp_code).first()
        user = get_object_or_404(models.User, phone=phone, otp_code=otp_code)
        # we assume 60 seconds for validation
        if user and get_time_diff(user.updated_at) <= 60:
            refresh = RefreshToken.for_user(user)
            tokens = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
            return Response({'tokens': tokens}, status=status.HTTP_201_CREATED)
        raise NotFound('User or OTP code is not valid', code=status.HTTP_204_NO_CONTENT)
