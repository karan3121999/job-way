from django.contrib import admin
from django.urls import path
from.views import *
urlpatterns = [
    path("test/",user_test,name="user_test"),

    path("user_signup",user_signup,name="user_signup"),
    path("",user_login,name="user_login"),
    path("user_logout/",user_logout,name="user_logout"),

    path("password_reset_request/",password_reset_request,name="password_reset_request"),
    path('password_reset_confirm/<uidb64>/<token>/',password_reset_confirm, name='password_reset_confirm'),
    path('change-password/', change_password, name='change_password'),



    path("companies_dashboard/",companies_dashboard,name="companies_dashboard"),
    path("create_job_posting/",Create_job_posting,name="create_job_posting"),



    path("candidates_dashboard/",candidates_dashboard,name="candidates_dashboard"),




]
