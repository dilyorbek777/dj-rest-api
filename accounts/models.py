import random
import uuid
from datetime import datetime, timedelta
from django.core.validators import FileExtensionValidator
from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken

from django.db import models
import uuid

class BaseModel(models.Model):
    id = models.UUIDField(unique=True, default=uuid.uuid4(), editable=False, primary_key=True)
    create_time = models.DateTimeField(auto_now_add=True)
    update_time = models.DateTimeField(auto_now=True)


    class Meta:
        abstract = True



ORDINARY = 'ordinary'
MANAGER = 'manager'
ADMIN = 'admin'
VIA_PHONE = 'via_phone'
VIA_EMAIL = 'via_email'
NEW = 'new'
CODE_VERIFY = 'code_verify'
DONE = 'done'
PHOTO_STEP = 'photo_step'
PHONE_EXPIRE = 2
EMAIl_EXPIRE = 5
class User(AbstractUser, BaseModel):
    USER_ROLES = (
        (ORDINARY, ORDINARY),
        (MANAGER, MANAGER),
        (ADMIN, ADMIN),
    )
    AUTH_TYPE = (
        (VIA_PHONE, VIA_PHONE),
        (VIA_EMAIL, VIA_EMAIL),
    )
    AUTH_STATUS = (
        (NEW, NEW),
        (CODE_VERIFY, CODE_VERIFY),
        (DONE, DONE),
        (PHOTO_STEP, PHOTO_STEP),
    )
    user_roles = models.CharField(max_length=30, choices=USER_ROLES, default=ORDINARY)
    auth_type = models.CharField(max_length=30, choices=AUTH_TYPE)
    auth_status = models.CharField(max_length=30, choices=AUTH_STATUS, default=NEW)
    email = models.EmailField(max_length=100, null=True, unique=True, blank=True)
    phone_number = models.CharField(max_length=13, null=True, unique=True, blank=True)
    photo = models.ImageField(upload_to='users_avatar/', null=True, blank=True, validators=[FileExtensionValidator(
        allowed_extensions=['jpg', 'jpeg', 'png', 'svg']
    )])


    def __str__(self):
        return self.username

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def create_verify_code(self, verify_type):
        code = "".join([str(random.randint(0, 10000) % 10) for _ in range(4)])
        UserConfirmation.objects.create(
            user_id=self.id,
            verify_type=verify_type,
            code=code
        )
        return code
    def check_username(self):
        if not self.username:
            temp_username = f'instagram-{uuid.uuid4().__str__().split("-")[-1]}'
            while User.objects.filter(username=temp_username):
                temp_username = f"{temp_username}{random.randint(0, 9)}"
            self.username = temp_username

    def check_email(self):
        if self.email:
            normalize_email = self.email.lower()
            self.email = normalize_email

    def check_pass(self):
        if not self.password:
            temp_password = f'password-{uuid.uuid4().__str__().split("-")[-1]}' #temp_pass -> temporary password
            self.password = temp_password

    def hashing_password(self):
        if not self.password.startswith('pbkdf2_sha256'):
            self.set_password(self.password)


    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        }


    def save(self, *args, **kwargs):
        self.clean()
        super(User, self).save(*args, **kwargs)
    def clean(self):
        self.check_email()
        self.check_username()
        self.check_pass()
        self.hashing_password()


class UserConfirmation(BaseModel):
    TYPE_VERIFY = (
        (VIA_PHONE,VIA_PHONE),
        (VIA_EMAIL, VIA_EMAIL),
    )

    code = models.CharField(max_length=4)
    verify_type = models.CharField(max_length=31, choices=TYPE_VERIFY)
    user = models.ForeignKey('accounts.User', models.CASCADE, related_name='verify_codes')
    expiration_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)
    objects = models.Manager()
    def __str__(self):
        return str(self.user.__str__())

    def save(self, *args, **kwargs):
        if self.verify_type == VIA_EMAIL:
            self.expiration_time = datetime.now() + timedelta(minutes=EMAIl_EXPIRE)
        else:
            self.expiration_time = datetime.now() + timedelta(minutes=PHONE_EXPIRE)
        super(UserConfirmation, self).save(*args, **kwargs)