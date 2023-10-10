from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers, exceptions
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken
from .utility import check_email_or_phone, send_email, send_phone_code, check_user_type
from rest_framework.exceptions import ValidationError, PermissionDenied
from django.db.models import Q
from .models import *

class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = (
            'id',
            'auth_type',
            'auth_status'
        )
        extra_kwargs = {
            'auth_type': {'read_only': True, 'required': False},
            'auth_status': {'read_only': True, 'required': False}
        }
    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
        user.save()
        return user

    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data
    @staticmethod
    def auth_validate(data):
        print(data)
        user_input = str(data.get('email_phone_number')).lower()
        input_type = check_email_or_phone(user_input)
        if input_type == 'email':
            data = {
                "email": user_input,
                'auth_type': VIA_EMAIL
            }
        elif input_type == 'phone':
            data = {
                "phone_number": user_input,
                'auth_type': VIA_PHONE
            }
        else:
            data = {
                "success": False,
                "message": "You must send phone number or email"
            }
            raise ValidationError(data)

        return data

    def validate_email_phone_number(self, value):
        value = value.lower()
        if value and User.objects.filter(email=value).exists():
            data = {
                "success": False,
                "Message": "This email already used !!!"
            }
            raise ValidationError(data)
        elif value and User.objects.filter(phone_number=value).exists():
            data = {
                "success": False,
                "Message": "This phone number already used !!!"
            }
            raise ValidationError(data)

        return value

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())
        return data

class ChangeUserInformation(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)
    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        if password != confirm_password:
            raise ValidationError({
                "Message": "Parollar bir biriga mos emas !"
            })
        if password:
            validate_password(password)
            validate_password(confirm_password)
        return data


    def validate_username(self, username):
        if len(username) < 5 or len(username) > 35:
            raise ValidationError(
                {
                    "Message": "username must be between 5 and 35 characters long"
                                   })
        if username.isdigit():
            raise ValidationError({
                "message": "This username is entirely numeric"
            })
        return username


    def update(self, instance, validated_data):
        instance.first_name = validated_data('first_name', instance.first_name)
        instance.last_name = validated_data('last_name', instance.last_name)
        instance.password = validated_data('password', instance.password)
        instance.username = validated_data('username', instance.username)
        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
        if instance.auth_status == CODE_VERIFY:
            instance.auth_status = DONE
        instance.save()
        return instance

class ChangeUserPhotoSerialzier(serializers.Serializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=[
        'jpg', 'png', 'jpeg', 'avif', 'heic', 'heif'
    ])])

    def update(self, instance, validated_data):
        photo = validated_data.get('photo')
        if photo:
            instance.photo = photo
            instance.auth_status = PHOTO_STEP
            instance.save()
            return instance
            
class LoginSerializer(TokenObtainPairSerializer):
    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['userinput'] = serializers.CharField(required=True)
        self.fields['username'] = serializers.CharField(required=False, read_only=True)
    
    def auth_validate(self, data):
        user_input = data.get("userinput")
        if check_user_type(user_input) == 'username':
            username = user_input
        elif check_user_type(user_input) == 'email':
            user = self.get_user(email__iexact=user_input)
            username = user
        elif check_user_type(user_input) == 'phone':
            user = self.get_user(phone_number=user_input)
            username = user
        else:
            data = {
                'success': False,
                "message": "You need to send email, username or phone number !!!"
            }
            raise ValidationError(data)
        authentication_kwargs = {
            self.username_field: username,
            'password': data['password']
        }
        
        current_user = User.objects.filter(user__iexact=username).first()
        if current_user is not None and current_user.auth_status in [NEW, CODE_VERIFY]:
            raise ValidationError({
                'success': False,
                'message': "You did not whole register"
            })
        user = authenticate(**authentication_kwargs)
        if user is not None:
            self.user = user
        else:
            data = {
                'success': False,
                'message': "Sorry, login or password you entered is incorrect, Please cheack and try again !!!"
            }
            raise ValidationError(data)
        
        
    def validate(self, data):
        self.auth_validate(data)
        if self.user.auth_status not in [DONE, PHOTO_STEP]:
            raise PermissionDenied("You can not login !!!")
        data = self.user.token()
        data['auth_status'] = self.user.auth_status
        data['full_name'] = self.user.full_name
        return data
    
    def get_user(self, **kwargs):
        users = User.objects.filter(**kwargs)
        if not users.exists():
            raise ValidationError({
                "message": "No active account found !!!"
            })
        return users.first()
        
class LoginRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        access_token_instance = AccessToken(data['access'])
        user_id = access_token_instance['user_id']
        user = get_object_or_404(User, id=user_id)
        update_last_login(None, user)
        return data

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()