from django.db import transaction
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.exceptions import NotFound
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from account import models, serializers
from account.util import generate_otp_code, get_time_diff


class HelloWorld(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    @staticmethod
    def get(request):
        return Response(({'hello world'}), status=status.HTTP_200_OK)


class PhoneValidationView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.PhoneValidationSerializer

    @staticmethod
    def post(request, *args, **kwargs):
        otp_code = generate_otp_code()
        phone = str(request.data['phone']).strip()
        verification_status = models.User.objects.filter(phone=phone).update(otp_code=otp_code,
                                                                             updated_at=timezone.now())

        if verification_status:
            return Response(({'otp': otp_code}), status=status.HTTP_201_CREATED)
        raise NotFound('Phone number not found', code=status.HTTP_204_NO_CONTENT)


class RegisterUserView(generics.ListCreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.UserSerializer
    queryset = models.User.objects.all()


class LoginView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.LoginSerializer

    @staticmethod
    def post(request, *args, **kwargs):

        phone = str(request.data['phone']).strip()
        otp_code = str(request.data['otp_code']).strip()
        user = models.User.objects.filter(phone=phone, otp_code=otp_code).first()
        # we assume 60 seconds for validation
        if user and get_time_diff(user.updated_at) <= 60:
            refresh = RefreshToken.for_user(user)
            tokens = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
            return Response({'tokens': tokens}, status=status.HTTP_201_CREATED)
        raise NotFound('User or OTP code is not valid', code=status.HTTP_204_NO_CONTENT)
