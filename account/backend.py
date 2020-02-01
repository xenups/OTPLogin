from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.db.models import Q

from account.models import User


class PhoneEmailUsernameBackend(object):
    def authenticate(self, request, username=None, password=None, **kwargs):
        my_user_model = get_user_model()
        try:
            user = User.objects.get(Q(username=username) | Q(email=username) | Q(phone=username))

            if user.check_password(password):
                return user  # return user on valid credentials
        except my_user_model.DoesNotExist:
            return None  # return None if custom user model does not exist
        except:
            return None  # return None in case of other exceptions

    def get_user(self, user_id):
        my_user_model = get_user_model()
        try:
            return my_user_model.objects.get(pk=user_id)
        except my_user_model.DoesNotExist:
            return None

    def validate_password(self, value: str) -> str:
        return make_password(value)
