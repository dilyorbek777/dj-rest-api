import os
from twilio.rest import Client
import re
import threading
import phonenumbers
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from rest_framework.exceptions import ValidationError


email_regex = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
phone_regex = re.compile(r"(\+[0-9]+\s*)?(\([0-9]+\))?[\s0-9\-]+[0-9]+")
username_regex = re.compile(f"^[a-zA-Z0-9_.-]+$")

def check_email_or_phone(email_or_phone):
    phone_number = phonenumbers.parse(email_or_phone, None)
    if re.fullmatch(email_regex, email_or_phone):
        email_or_phone = "email"
    elif phonenumbers.is_valid_number(phone_number):
        email_or_phone = "phone"
    else:
        data = {
            "success": False,
            'message': "Email or Phone Number were an error, please try again."
        }
        raise ValidationError(data)
    return email_or_phone

def check_user_type(user_input):
    if re.fullmatch(email_regex, user_input):
        user_input = "email"
    elif re.fullmatch(username_regex, user_input):
        user_input = 'username'
    elif re.fullmatch(phone_regex, user_input):
        user_input = "phone"
    else:
        data = {
            "success": False,
            "message": "Email, Username or phone number are wrong !!!"
        }
        raise ValidationError(data)
    return user_input

class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)


    def run(self):
        self.email.send()

class Email:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            to=[data['to_email']]
        )
        if data.get('content_type') == 'html':
            email.content_subtype = 'html'
        EmailThread(email).start()

def send_email(email, code):
    html_content = render_to_string(
        'email/activate.html',
        {"code": code}
    )
    Email.send_email(
        {
            "subject": "Register",
            "to_email": email,
            "body": html_content,
            "content_type": 'html'
        }
    )

def send_phone_code(phone, code):
    account_sid = os.environ['MG87c7458ba92dbe77042a3f9e2f684ab0']
    auth_token = os.environ['AC4632189e14a0a67a66d3fad7c291af00']
    client = Client(account_sid, auth_token)
    message = client.messages \
        .create(
        body = f"Hello My Friend, Your DRF code is {code}",
        from_ = '+998904598206',
        to = f"{phone}"
    )