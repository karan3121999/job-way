from django.shortcuts import render
from django.shortcuts import render, redirect,HttpResponse
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.urls import reverse
from .forms import PasswordResetRequestForm
from django.contrib.auth.forms import SetPasswordForm
from django.conf import settings
from.models import*
import re
from.tasks import send_reset_email,send_signup_email
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import secrets
from django.core.files.base import ContentFile
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.views.decorators.csrf import ensure_csrf_cookie

# Create your views here.


def user_test(request):
    return render(request,"test.html")

def main(request):
    if request.user.is_superuser:
        users = CustomUser.objects.all()
        return render(request, 'admin_dashboard.html', {'users': users})
    else:
        return render(request,"user_dashboard.html")

def user_signup(request):
    active_tab = 'job_provider'  # Default active tab

    if request.method == 'POST':
        user_type = request.POST.get('user_type')
        email = request.POST.get('email')
        username=request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        terms_condition = request.POST.get('terms_condition')

        if not terms_condition:
            messages.error(request, 'You must agree to the terms and conditions.')
            active_tab = user_type
        elif password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            active_tab = user_type
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messages.error(request, 'Invalid email format.')
            active_tab = user_type
        elif CustomUser.objects.filter(email=email).exists():
            messages.error(request, 'Email already taken.')
            active_tab = user_type
        else:
            if user_type == 'job_provider':
                user = CustomUser.objects.create_user(email=email,username=username, password=password, is_jobProvider=True)
                send_signup_email(username=username,email=email,password=password,user_type=user_type)
                messages.success(request, f"Thanks! {username} You are registered as a job provider")
            elif user_type == 'job_seeker':
                user = CustomUser.objects.create_user(email=email,username=username, password=password, is_jobSeeker=True)
                send_signup_email(username=username,email=email,password=password,user_type=user_type)
                messages.success(request, f"Thanks! {username} You are registered as a job seeker")
            else:
                messages.error(request, 'Invalid user type.')
                active_tab = user_type
            return render(request, 'auth/login.html', {'active_tab': user_type})

    return render(request, 'auth/signup.html', {'active_tab': active_tab})



def user_login(request):
    """
    Handles user login by authenticating credentials and managing session.

    If the request method is POST, it retrieves the username and password
    from the request, authenticates the user, and logs them in if valid.
    On successful login, redirects the user to their respective dashboard
    based on their user type (job provider or job seeker).
    Displays an error message if authentication fails.
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            messages.success(request, 'Login successful!')
            
            # Redirect based on user type
            if user.is_jobProvider:
                return redirect('companies_dashboard')  
            elif user.is_jobSeeker:
                return redirect('candidates_dashboard')
        else:
            messages.error(request, 'Invalid credentials.')
    return render(request, 'auth/login.html')




def user_logout(request):
    auth_logout(request)
    return redirect('user_login')




def password_reset_request(request):
    """
    Handles password reset requests. If the request method is POST and the form is valid, it sends a password reset email to associated users.
    Uses Celery for asynchronous email sending. Renders different templates based on success or error.
    """
    if request.method == "POST":
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            associated_users = CustomUser.objects.filter(email=email)
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email = user.email

                    # Get or create the UserPasswordMechanism for this user
                    password_mechanism, created = UserPasswordMechanism.objects.get_or_create(user=user)

                    # Generate and set a new token
                    token = password_mechanism.set_password_reset_token()
                    context = {
                        "email": user.email,
                        'domain': request.META['HTTP_HOST'],
                        'site_name': 'Jobs Way',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user_id": user.pk,
                        'token': token,
                        'protocol': 'http' if not request.is_secure() else 'https',
                    }
                    # celery
                    send_reset_email(subject, context, email)
                    return render(request, "auth/password_reset_done.html")
            else:
                messages.error(request, 'No user is associated with this email address.')
    form = PasswordResetRequestForm()
    return render(request=request, template_name="auth/password_reset_request.html", context={"form": form})



# def password_reset_done(request):
#     return render(request,"auth/password_reset_confirm.html")

def password_reset_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = CustomUser.objects.get(pk=uid)
        password_mechanism = UserPasswordMechanism.objects.get(user=user)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist, UserPasswordMechanism.DoesNotExist):
        user = None
        password_mechanism = None

    if user is not None and password_mechanism is not None and password_mechanism.is_password_reset_token_valid(token):
        if request.method == 'POST':
            new_password1 = request.POST.get('new_password1')
            new_password2 = request.POST.get('new_password2')
            form = SetPasswordForm(user, data={
                'new_password1': new_password1,
                'new_password2': new_password2
            })
            if form.is_valid():
                form.save()
                password_mechanism.password_reset_token = ''
                password_mechanism.password_reset_token_created = None
                password_mechanism.save()
                messages.success(request, 'Your password has been reset. You can now log in with your new password.')
                return redirect('user_login')
            else:
                messages.error(request, 'There was an error with the form. Please correct the errors and try again.')
        else:
            form = SetPasswordForm(user)

        return render(request, 'auth/password_reset_confirm.html', {'form': form})
    else:
        messages.error(request, 'The password reset link is invalid or has expired.')
        return redirect('password_reset_request')



@login_required
def change_password(request):
    if request.method == 'POST':
        old_password = request.POST['old_password']
        new_password1 = request.POST['new_password1']
        new_password2 = request.POST['new_password2']

        user = request.user

        if not user.check_password(old_password):
            messages.error(request, 'Your old password was entered incorrectly. Please enter it again.')
        elif new_password1 != new_password2:
            messages.error(request, 'The two password fields didnt match.')
        elif len(new_password1) < 8:
            messages.error(request, 'Your new password must be at least 8 characters long.')
        else:
            user.set_password(new_password1)
            user.save()
            update_session_auth_hash(request, user)  
            messages.success(request, 'Your password was successfully updated! please login again')
            return redirect('user_login')  

    return render(request, 'auth/change_password.html')



@require_http_methods(["GET", "POST"])
def companies_dashboard(request):
    user = request.user
    needs_profile = user.is_jobProvider

    # Try to get the existing company profile for the user
    try:
        profile = Company_profile.objects.get(user=user)
    except Company_profile.DoesNotExist:
        profile = None

    if request.method == "POST":
        profile_pic = request.FILES.get("profile_pic")
        company_name = request.POST.get("company_name")
        contact_information = request.POST.get("contact_information")
        description = request.POST.get("description")
        location = request.POST.get("location")

        if profile:
            # Update existing profile
            profile.company_name = company_name
            profile.contact_information = contact_information
            profile.description = description
            profile.location = location
            if profile_pic:  # Only update if a new picture is uploaded
                profile.profile_pic = profile_pic
            profile.save()

            if request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
                return JsonResponse({"success": True, "message": "Profile updated successfully!"})
            messages.success(request, "Profile updated successfully!")
        else:
            # Create a new profile
            try:
                profile = Company_profile.objects.create(
                    user=user,
                    company_name=company_name,
                    contact_information=contact_information,
                    description=description,
                    location=location,
                    profile_pic=profile_pic
                )
                if request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
                    return JsonResponse({"success": True, "message": "Profile created successfully!"})
                messages.success(request, "Profile created successfully!")
            except Exception as e:
                if request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
                    return JsonResponse({"success": False, "message": str(e)}, status=400)
                messages.error(request, f"An error occurred: {str(e)}")
        
        return redirect('companies_dashboard')

    context = {
        'needs_profile': needs_profile,
        'profile': profile,  # Pass the profile to the template
    }
    return render(request, "companies_dashboard.html", context)


@require_http_methods(["GET", "POST"])
def Create_job_posting(request):
    if request.method == 'POST':
        try:
            # Try to parse JSON data
            data = json.loads(request.body)
            print("data_json::::",data)
        except json.JSONDecodeError:
            # If not JSON, use POST data
            data = request.POST
            print("data:::::::",data)

        company = data.get('company')
        title = data.get('title')
        description = data.get('description')
        requirements = data.get('requirements')
        location = data.get('location')
        salary = data.get('salary')

        # Create a new Job object and save it to the database
        job = Job.objects.create(
            title=title,
            description=description,
            requirements=requirements,
            company=company,
            location=location,
            salary=salary
        )
        job.save()
        messages.success(request,"your job has been created")
        return redirect("companies_dashboard")
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})






def candidates_dashboard(request):
    return render(request,"candidates_dashboard.html")