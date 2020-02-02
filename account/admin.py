from django.contrib import admin

from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from account.models import User


class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = ('username', 'email')


class UserAdminModel(UserAdmin):
    readonly_fields = ["date_joined"]
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {'fields': ('email', 'phone', 'first_name', 'last_name')}),
    )


admin.site.register(User, UserAdminModel)
