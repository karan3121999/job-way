from celery import Celery
from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.contrib.auth import get_user_model



def send_reset_email(subject, context, to_email):
   
        email_content = f"""
                                Hello {context['email']},

                                You're receiving this email because you requested a password reset for your user account at {context['site_name']}.

                                Please click the link below to reset your password:

                                {context['protocol']}://{context['domain']}/password_reset_confirm/{context['uid']}/{context['token']}/

                                If you didn't request a password reset, you can safely ignore this email.

                                Thanks,
                                Your team
                                        """
        
        send_mail(
            subject=subject,
            message=email_content,
            from_email=settings.EMAIL_HOST_USER,  # Correct argument name
            recipient_list=[to_email]

        )
     


def send_signup_email(username, email,password,user_type):
    subject = 'Welcome to Our Platform!'
    message = f"""Hi {username},

        Thank you for registering at Jobs_Way.
        You are registered as :{user_type}

        Your account details are as follows:
            Username: {username}
            Email: {email}
            Password: {password}

        Please keep this information secure.

        Best regards,
        Jobs_Way Team
        """
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)