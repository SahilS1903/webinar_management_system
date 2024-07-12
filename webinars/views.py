from django.shortcuts import render
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import *  # Import User model
from django.contrib.auth import authenticate, login
import re
from datetime import datetime, timedelta
from django.shortcuts import render,redirect,reverse
from . import forms,models
from django.db.models import Sum
from django.contrib.auth.models import Group
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import login_required,user_passes_test
from django.conf import settings
from datetime import date, timedelta
from django.db.models import Q
from django.core.mail import send_mail

from django.contrib.auth.models import User

from webinars.models import User, Profile,Webinar




def home_view(request):
    if request.user.is_authenticated:
        if request.user.profile.role=='Host':
            return host_dashboard(request)
        elif request.user.profile.role=='User':
            return user_dashboard(request)
        else:
            return admin_dashboard(request)
    else:
        return render(request, 'index.html')
    
def aboutus_view(request):
    return render(request,'aboutus.html')

def contactus_view(request):
    sub = forms.ContactusForm()
    if request.method == 'POST':
        # sub = forms.ContactusForm(request.POST)
        # if sub.is_valid():
            email = request.POST.get('Email')
            name=  request.POST.get('Name')
            message = request.POST.get('Message')
            send_mail(str(name)+' || '+str(email),message,settings.EMAIL_HOST_USER, settings.EMAIL_RECEIVING_USER, fail_silently = False)
            return render(request, 'contactussuccess.html')
    return render(request, 'contactus.html', {'form':sub})




def userclick_view(request):
    # if request.user.is_authenticated:
    #     return HttpResponseRedirect('afterlogin')
    return render(request,'userclick.html')

def signup_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        fname = request.POST.get('fname')
        lname = request.POST.get('lname')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        role=request.POST.get('role')
        # login_as = request.POST.get('login_type')
        
        # Validate input data
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$', email):
            messages.error(request, 'Invalid email format. Please enter a valid email address.')
            return redirect('signup')
        if len(username) < 8 or not re.match(r'^[a-zA-Z0-9]+$', username):
            messages.error(request, 'Username must be at least 8 characters long and contain only alphanumeric characters.')
            return redirect('signup')
        if len(fname) < 2 or not re.match(r'^[a-zA-Z ]+$', fname):
            messages.error(request, 'Invalid name format. Please enter a valid name.')
            return redirect('signup')
        if len(password) < 8 or not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=])(?=\S+$).{8,}$', password):
            messages.error(request, 'Please enter a strong password.')
            return redirect('signup')
        
        # Check if the username or email already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists. Please choose another username.')
            return redirect('signup')
            
            
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email address already exists. Please enter another email.')
            return redirect('signup')
        if password!=password2:
            messages.error(request, 'Passwords do not match. Please re-check your password!')
            return redirect('signup')
        
        # Create new user with create_user() method of CustomUser manager
        if role=="Host":
            user = User.objects.create_user(username=username, email=email, password=password, first_name=fname, last_name=lname)
            user_profile = Profile.objects.create(user=user,role=role,status=False)
        else:
            user = User.objects.create_user(username=username, email=email, password=password, first_name=fname, last_name=lname)
            user_profile = Profile.objects.create(user=user,role=role,status=True)    
        if role=="Host":
            messages.success(request, 'Host added successfully')
        else:
            messages.success(request, 'User added successfully')
        return redirect('home')
        
    return render(request, 'signup.html')

def is_user(user):
    return user.groups.filter(name='user').exists()



@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_approval_view(request):
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    pending_hosts = Profile.objects.filter(role='Host', status=False)
    if request.method == 'POST':
        action = request.POST.get('action')
        selected_hosts = request.POST.getlist('selected_hosts')
        for host_id in selected_hosts:
            host = Profile.objects.get(pk=host_id)
            if action == 'approve':
                host.status = True
                host.save
            elif action == 'reject':
                host.user.delete()  # Delete the user and associated profile
            host.save()    
        return redirect('admin_approval')
    return render(request, 'admin_approval.html', {'pending_hosts': pending_hosts,'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})




def userlogin_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Authenticate user directly with authenticate()
        user = authenticate(request, username=username, password=password)
 
        if user is not None:
            try:
                user_profile = Profile.objects.get(user=user, role='User')
                if user_profile.status:
                    login(request, user)
                    print("User logged in successfully:", user)
            # Redirect user based on login_as
                return redirect('home')
            except Profile.DoesNotExist:
                    messages.error(request, 'Invalid credentials.')
            
        else:
            messages.error(request, 'Invalid email or password')
            # If credentials are incorrect, render the login page again
            return render(request, 'user_login.html')

    # If request method is not POST, render the login page
    return render(request, 'user_login.html')


from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Announcement, Profile

def host_login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Authenticate user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Check if the user is a host and is approved
            try:
                host_profile = Profile.objects.get(user=user, role='Host')
                if host_profile.status:
                    # Login user
                    login(request, user)
                    return redirect('home')
                else:
                    
                    return render(request,'host_wait.html')
            except Profile.DoesNotExist:
                messages.error(request, 'Invalid credentials.')

        else:
            messages.error(request, 'Invalid credentials.')

    return render(request, 'host_login.html')


@login_required
def user_dashboard(request):
    profile = Profile.objects.filter(user=request.user).first()
    announcements = Announcement.objects.all()
    if request.user.is_authenticated:
        # Retrieve the avatar field from the profile object
        profile_avatar = profile.avatar if profile else None
        return render(request, 'user_dashboard.html', {'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar,'announcements': announcements})
    else:
        return render(request, 'index.html')
@login_required
def host_dashboard(request):
    profile = Profile.objects.filter(user=request.user).first()
    if request.user.is_authenticated:
        # Retrieve the avatar field from the profile object
        profile_avatar = profile.avatar if profile else None
        return render(request, 'host_dashboard.html', {'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})
    else:
        return render(request, 'index.html')

@login_required
def admin_dashboard(request):
    profile = Profile.objects.filter(user=request.user).first()
    if request.user.is_authenticated:
        # Retrieve the avatar field from the profile object
        profile_avatar = profile.avatar if profile else None
        return render(request, 'admin_dashboard.html', {'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})
    else:
        return render(request, 'index.html')

    



from django.db.models import Q
from django.utils import timezone
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.utils.html import strip_tags
from django.core.mail import EmailMessage

@login_required
def create_webinar(request):
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        date = request.POST.get('date')
        start_time = request.POST.get('start_time')
        duration_hours = int(request.POST.get('duration_hours'))
        
        
        start_datetime = f"{date} {start_time}"
        
        # Calculate end time based on start time and duration
        start_datetime_obj = datetime.strptime(start_datetime, '%Y-%m-%d %H:%M')
        end_datetime_obj = start_datetime_obj + timedelta(hours=duration_hours)
        end_time = end_datetime_obj.time().strftime('%H:%M')

        # Get the current user as the host
        host = request.user

        # Check if the host already has a webinar scheduled during the same time
        if Webinar.objects.filter(
            Q(host=host),
            Q(date=date),
            (
                Q(start_time__lte=start_time, end_time__gte=start_time) |
                Q(start_time__lte=end_time, end_time__gte=end_time) |
                Q(start_time__gte=start_time, end_time__lte=end_time)
            )
        ).exists():
            messages.error(request, 'You already have a webinar scheduled during the same time period.')
            return redirect('create_webinar')

        # Create a new Webinar object
        webinar = Webinar.objects.create(
            title=title,
            description=description,
            date=date,
            start_time=start_time,
            end_time=end_time,
            duration_hours=duration_hours,
            host=host,
            
        )
        webinar.save()

        messages.success(request,'Webinar created successfully!')

        if request.method == 'POST':
    # Create a list of email recipients (users with role=='User')
            user_emails = User.objects.filter(profile__role='User').values_list('email', flat=True)
    
    # Compose the email message
            subject = 'New Webinar Created'
            html_message = render_to_string('email/webinar_created_email.html', {
                'webinar_title': title,
                'webinar_description': description,
                'host_name': request.user.get_full_name(),
                'webinar_date': date,
                'duration_hours': duration_hours,
                'start_time': start_time,
                'end_time': end_time,
        # Add more details as needed...
            })
            

            email = EmailMessage(
            subject=subject,
            body=html_message,  # You can include both HTML and plain text content here
            from_email=settings.EMAIL_HOST_USER,  # Update with your sender email
            to=[],  # List of recipient email addresses
            bcc=user_emails,  # List of Bcc recipient email addresses
        )
            email.content_subtype = 'html'
            email.send(fail_silently=False)

    # Create a plain text version of the email content
    #         plain_message = strip_tags(html_message)

    #         sender_email = settings.EMAIL_HOST_USER  # Update with your sender email
    #         recipient_emails = user_emails  # List of recipient email addresses

    # # Send the email
    #         send_mail(subject, plain_message, sender_email, bcc=recipient_emails, html_message=html_message, fail_silently=False)

        # Redirect to the home page or any other appropriate page
        
        return redirect('home')  # Assuming 'home' is the name of your home page URL
    return render(request, 'create_webinar.html', {'user': request.user, 'profile': profile,'profile_avatar': profile_avatar})

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import Webinar,Feedback
from .models import Registration

@login_required()
def my_upcoming_webinars(request):
    current_datetime = timezone.now()
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    
    upcoming_webinars = Webinar.objects.filter(
    host=request.user,
    date__gte=current_datetime.date(),
    
    )
    
    for webinar in upcoming_webinars:
        registrations = Registration.objects.filter(webinar=webinar).select_related('user')
        webinar.registrations = registrations.count()  # Attach registrations data to each webinar object
    
    return render(request, 'my_upcoming_webinars.html', {'upcoming_webinars': upcoming_webinars, 'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})

@login_required()
def admin_webinar_registration(request):
    
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    
    upcoming_webinars = Webinar.objects.all()
    
    for webinar in upcoming_webinars:
        registrations = Registration.objects.filter(webinar=webinar).select_related('user')
        webinar.registrations = registrations.count()  # Attach registrations data to each webinar object
    
    return render(request, 'admin_webinar_registration.html', {'upcoming_webinars': upcoming_webinars, 'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})
@login_required()
def admin_remove_announcements(request):
    
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    
    announcements = Announcement.objects.all()
    
    return render(request, 'admin_remove_announcements.html', {'announcements': announcements, 'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})

@login_required()
def admin_user_list(request):
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    
    users = User.objects.all()
    
    return render(request, 'admin_user_list.html', {'users': users, 'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})
@login_required()
def my_past_webinars(request):
    current_datetime = timezone.now()
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    
    past_webinars = Webinar.objects.filter(
    host=request.user,
    start_time__lt=current_datetime.time(),
    date__lt=current_datetime.date()
    )

    
    for webinar in past_webinars:
        registrations = Registration.objects.filter(webinar=webinar).select_related('user')
        webinar.registrations = registrations.count()  # Attach registrations data to each webinar object
    
    return render(request, 'my_past_webinars.html', {'past_webinars': past_webinars, 'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})

    
    # Update the registrations count for each webinar
@login_required()
def delete_webinar(request, webinar_id):
    # Get the webinar object
    webinar = Webinar.objects.get(pk=webinar_id)
    
    # Check if the current user is the host of the webinar
    if request.user == webinar.host:
        announcement_title = f"Webinar '{webinar.title}' Deleted"
        announcement_content = f"The webinar '{webinar.title}' scheduled for {webinar.date} has been deleted."
        announcement = Announcement.objects.create(title=announcement_title, content=announcement_content)
        # Delete the webinar
        webinar.delete()
        messages.success(request, 'Webinar deleted successfully.')
    else:
        messages.error(request, 'You are not authorized to delete this webinar.')
    
    # Redirect back to the upcoming webinars page
    return HttpResponseRedirect(reverse('my_upcoming_webinars'))
from django.shortcuts import get_object_or_404

@login_required()
def admin_delete_webinar(request, webinar_id):
    # Get the webinar object or raise a 404 error if not found
    webinar = get_object_or_404(Webinar, pk=webinar_id)
    
    # Check if the current user is the host of the webinar
    if request.user.profile.role == 'Admin':
        announcement_title = f"Webinar '{webinar.title}' Deleted"
        announcement_content = f"The webinar '{webinar.title}' scheduled for {webinar.date} has been deleted."
        announcement = Announcement.objects.create(title=announcement_title, content=announcement_content)
        # Delete the webinar
        webinar.delete()
        messages.success(request, 'Webinar deleted successfully.')
    else:
        messages.error(request, 'You are not authorized to delete this webinar.')
    
    # Redirect back to the upcoming webinars page
    return HttpResponseRedirect(reverse('admin_webinar_registration'))



from django.shortcuts import get_object_or_404, HttpResponseRedirect, reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

@login_required
def delete_user(request, user_id):
    try:
        # Get the user object
        user = get_object_or_404(User, pk=user_id)
        
        # Check if the current user is authorized to delete users
        if request.user.profile.role == 'Admin':
            # Delete the user
            user.delete()
            messages.success(request, 'User deleted successfully.')
        else:
            messages.error(request, 'You are not authorized to delete users.')
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
    
    # Redirect back to the user list page
    return HttpResponseRedirect(reverse('admin_user_list'))
@login_required
def delete_announcements(request, announcement_id):
    try:
        # Get the user object
        announcement = get_object_or_404(Announcement, pk=announcement_id)
        
        # Check if the current user is authorized to delete users
        if request.user.profile.role == 'Admin':
            # Delete the user
            announcement.delete()
            messages.success(request, 'Announcement deleted successfully.')
        else:
            messages.error(request, 'You are not authorized to delete users.')
    except User.DoesNotExist:
        messages.error(request, 'Announcement not found.')
    
    # Redirect back to the user list page
    return HttpResponseRedirect(reverse('admin_remove_announcements'))

   
    
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

def change_password(request):
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_new_password = request.POST.get('confirm_new_password')

        # Check if the current password is correct
        if not request.user.check_password(current_password):
            messages.error(request, 'Incorrect current password.')
            return redirect('change_password')

        # Validate the new password
        try:
            validate_password(new_password)
        except ValidationError as e:
            messages.error(request, e)
            return redirect('change_password')

        # Check if the new password matches the confirmation
        if new_password != confirm_new_password:
            messages.error(request, 'New password and confirmation do not match.')
            return redirect('change_password')

        # Change the user's password
        request.user.set_password(new_password)
        request.user.save()

        messages.success(request, 'Password changed successfully.')
        return redirect('home')

    return render(request, 'change_password.html',{'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})


def profile_view(request):
    if request.user.is_authenticated:
        profile, created = Profile.objects.get_or_create(user=request.user)
        profile_avatar = profile.avatar if profile else None
        
        if request.method == 'POST':
            # Update user data
            request.user.first_name = request.POST.get('first_name', '')
            request.user.last_name = request.POST.get('last_name', '')
            # request.user.email = request.POST.get('email', '')
            request.user.save()

            # Update profile data
            profile.bio = request.POST.get('bio', '')
            profile.state = request.POST.get('state', '')
            profile.city = request.POST.get('city', '')
            profile.phone = request.POST.get('phone', '')
            dob = request.POST.get('dob', '')  # Get dob from POST data
            if dob:  # Check if dob is provided
                profile.dob = dob
            profile.gender = request.POST.get('gender', '')
            profile.address = request.POST.get('address', '')
            avatar = request.FILES.get('avatar')
            if avatar:
                profile.avatar = avatar
            profile.save()

            return redirect('profile')  # Redirect to the profile page after saving
        return render(request, 'profile.html', {'user': request.user, 'profile': profile,'profile_avatar': profile_avatar})
    else:
        return render(request, 'home.html')  # Render login page if user is not authenticated

    
from django.shortcuts import render, redirect, HttpResponse
from .models import Webinar, Registration

from datetime import datetime
from django.utils import timezone

from datetime import datetime
from django.utils import timezone

def join_webinar(request):
    try:
        profile, created = Profile.objects.get_or_create(user=request.user)
        profile_avatar = profile.avatar if profile else None
        registered_webinars = Registration.objects.filter(user=request.user).select_related('webinar')
        
        print("Number of registered webinars:", registered_webinars.count())  # Debug statement
        
        # Filter only upcoming webinars
        upcoming_webinars = registered_webinars.filter(webinar__date__gte=timezone.now().date())
        
        print("Number of upcoming webinars:", upcoming_webinars.count())  # Debug statement
        
        return render(request, 'join_webinar.html', {
            'registered_webinars': upcoming_webinars,
            'user': request.user,
            'profile': profile,
            'profile_avatar': profile_avatar
        })
    except Exception as e:
        print("Error in join_webinar view:", e)  # Debug statement
        # Handle the error gracefully, render an error page or return an empty response
        return HttpResponse("An error occurred. Please try again later.")



from datetime import datetime

from datetime import datetime

def register_webinar(request, webinar_id):
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    webinar = Webinar.objects.get(pk=webinar_id)
    user = request.user

    # Get the current datetime
    current_time = datetime.now()

    # Check if the webinar has already ended
    if datetime.combine(webinar.date, webinar.end_time) < current_time:
        messages.error(request, "This webinar has already occurred and cannot be registered for.")
        return redirect('home')

    if request.user == webinar.host:
        messages.error(request, "You cannot register for your own webinar.")
        return render(request, 'webinar_list.html', {'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})

    if Registration.objects.filter(Q(webinar=webinar) & Q(user=user)).exists():
        messages.error(request, 'You are already registered for this webinar.')
    else:
        # If not registered, create a registration entry for the user
        registration = Registration.objects.create(webinar=webinar, user=user)
        registration.save()
        messages.success(request, 'Successfully registered for the webinar.')
    return redirect('home')

from django.utils import timezone

def webinar_list(request):
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    current_datetime = timezone.now()
    # Fetch all available webinars
    webinars = Webinar.objects.filter(
    date__gte=current_datetime.date(),
    )
    return render(request, 'webinar_list.html', {'webinars': webinars,'user': request.user, 'profile': profile,'profile_avatar': profile_avatar})


def my_registrations(request):
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    # Fetch registrations made by the current user
    registrations = Registration.objects.filter(user=request.user).select_related('webinar')
    return render(request, 'my_registrations.html', {'registrations': registrations,'user': request.user, 'profile': profile,'profile_avatar': profile_avatar})



def webinar_registered_users(request, webinar_id):
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    webinar = Webinar.objects.get(pk=webinar_id)
    registrations = Registration.objects.filter(webinar=webinar).select_related('user')
    registered_users = [registration.user for registration in registrations]
    return render(request, 'webinar_registered_users.html', {'webinar': webinar, 'registered_users': registered_users,'registrations': registrations,'user': request.user, 'profile': profile,'profile_avatar': profile_avatar})

from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Announcement
from datetime import datetime, timedelta

def create_announcement(request):
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    if request.method == 'POST':
        
        title = request.POST.get('title')
        content = request.POST.get('content')
        
        # Create the announcement object
        announcement = Announcement(title=title, content=content)
        
        # Set the expiration date to 1 day from now
        expiration_date = datetime.now() + timedelta(days=1)
        announcement.expiration_date = expiration_date
        
        # Save the announcement
        announcement.save()
        
        messages.success(request, 'Announcement created successfully!')
        return redirect('home')  # Redirect to a page showing all announcements
    return render(request, 'create_announcement.html',{'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})



from django.shortcuts import render, redirect
from django.utils import timezone
from .models import Webinar

from django.shortcuts import render, redirect
from django.utils import timezone
from .models import Webinar, Feedback

from django.shortcuts import render, redirect
from .models import Webinar
from django.utils import timezone

from django.utils import timezone

from django.db.models import Q

from django.utils import timezone
from django.db.models import Q

@login_required
def select_webinar(request):
    user = request.user
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    
    # Retrieve the IDs of webinars the user is registered for
    registered_webinar_ids = Registration.objects.filter(user=user).values_list('webinar_id', flat=True)
    
    # Filter webinars based on user registration and other criteria
    attended_webinars = Webinar.objects.filter(
        Q(id__in=registered_webinar_ids),  # Filter webinars user is registered for
        end_time__lte=timezone.now(),      # Filter webinars that have ended
        feedback__isnull=True,              # Filter webinars with no feedback provided
        date__lt=timezone.now().date()     # Filter out future webinars
    )
    
    return render(request, 'select_webinar.html', {'attended_webinars': attended_webinars,'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})


def feedback_form(request, webinar_id):
    user = request.user
    webinar = Webinar.objects.get(pk=webinar_id)
    profile, created = Profile.objects.get_or_create(user=request.user)
    profile_avatar = profile.avatar if profile else None
    
    if request.method == 'POST':
        content_rating = int(request.POST.get('content'))
        presentation_rating = int(request.POST.get('presentation'))
        interactivity_rating = int(request.POST.get('interactivity'))
        overall_rating = int(request.POST.get('overall'))
        comments = request.POST.get('comments')

        feedback = Feedback.objects.create(
            webinar=webinar,
            user=user,
            content_rating=content_rating,
            presentation_rating=presentation_rating,
            interactivity_rating=interactivity_rating,
            overall_rating=overall_rating,
            comments=comments
        )
        messages.success(request,'Your feedback has been submitted!')
        return redirect('home')  # Redirect to a thank you page
        

    return render(request, 'feedback_form.html', {'webinar': webinar,'user': request.user, 'profile': profile, 'profile_avatar': profile_avatar})

@login_required
def view_feedback(request, webinar_id):
    user = request.user
    profile, created = Profile.objects.get_or_create(user=user)
    profile_avatar = profile.avatar if profile else None

    # Retrieve the feedback for the selected webinar
    feedbacks = Feedback.objects.filter(webinar_id=webinar_id)

    return render(request, 'host_feedback.html', {'feedbacks': feedbacks, 'user': user, 'profile': profile, 'profile_avatar': profile_avatar})

@login_required
def select_hosted_webinars(request):
    user = request.user
    profile, created = Profile.objects.get_or_create(user=user)
    profile_avatar = profile.avatar if profile else None

    # Retrieve the webinars hosted by the user
    hosted_webinars = Webinar.objects.filter(host=user)

    return render(request, 'select_hosted_webinars.html', {'hosted_webinars': hosted_webinars, 'user': user, 'profile': profile, 'profile_avatar': profile_avatar})
