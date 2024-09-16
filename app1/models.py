from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.utils import timezone
import secrets
# Create your models here.


class CustomUser(AbstractUser):
    is_jobProvider=models.BooleanField(default=False)
    is_jobSeeker=models.BooleanField(default=False)

    def __str__(self) -> str:
        return self.username
    

class UserPasswordMechanism(models.Model):
    user = models.OneToOneField('CustomUser', on_delete=models.CASCADE, related_name='password_mechanism')
    password_reset_token = models.CharField(max_length=100, blank=True)
    password_reset_token_created = models.DateTimeField(null=True)

    def set_password_reset_token(self):
        token = secrets.token_urlsafe(32)
        self.password_reset_token = token
        self.password_reset_token_created = timezone.now()
        self.save()
        return token

    def is_password_reset_token_valid(self, token):
        if not self.password_reset_token or self.password_reset_token != token:
            return False
        if not self.password_reset_token_created:
            return False
        if (timezone.now() - self.password_reset_token_created).total_seconds() > 300:  # 5 minutes
            return False
        return True
    

class Company_profile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    company_name = models.CharField(max_length=100, null=True)
    contact_information = models.CharField(max_length=100, null=True)
    description = models.CharField(max_length=100, null=True)
    location = models.CharField(max_length=255, null=True, blank=True)
    profile_pic = models.ImageField(upload_to='profile_pics/', null=True, blank=True) 

    def __str__(self) -> str:
        return self.company_name




class Job(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    requirements = models.TextField()
    company = models.CharField(max_length=100)
    location = models.CharField(max_length=100)
    salary = models.CharField(max_length=100, blank=True, null=True)
    posted_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.title

class Application(models.Model):
    job = models.ForeignKey(Job, on_delete=models.CASCADE, related_name='applications')
    applicant = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='applications')
    resume = models.FileField(upload_to='resumes/')
    cover_letter = models.TextField()
    applied_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('reviewed', 'Reviewed'),
        ('interviewed', 'Interviewed'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected')
    ], default='pending')

    def __str__(self):
        return f"{self.applicant.username}'s application for {self.job.title}"