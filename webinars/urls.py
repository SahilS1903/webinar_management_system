from django.urls import path

from webinars import admin
from . import views
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LoginView
from django.contrib import admin


urlpatterns = [
    path('', views.home_view, name='home'),
    path('aboutus', views.aboutus_view),
    path('contactus', views.contactus_view),
    path('userlogin/', views.userlogin_view, name='userlogin'),
    path('hostlogin/', views.host_login_view, name='hostlogin'),
    path('adminlogin', LoginView.as_view(template_name='admin_login.html'),name='adminlogin'),
    path('signup/', views.signup_view,name='signup'),
    path('approval/', views.admin_approval_view, name='admin_approval'),
    
    path('user_dashboard/', views.user_dashboard, name='user_dashboard'),
    path('host_dashboard/', views.host_dashboard, name='host_dashboard'),
    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('logout/', auth_views.LogoutView.as_view(template_name='logout.html'), name='logout'),
    path("create_webinar/", views.create_webinar, name='create_webinar'),
    path('my-upcoming-webinars/', views.my_upcoming_webinars, name='my_upcoming_webinars'),
    path('admin_webinar_registration/', views.admin_webinar_registration, name='admin_webinar_registration'),
    path('admin_user_list/', views.admin_user_list, name='admin_user_list'),
    path('admin_remove_announcements/', views.admin_remove_announcements, name='admin_remove_announcements'),
    path('my-past-webinars/', views.my_past_webinars, name='my_past_webinars'),
    path("profile/", views.profile_view, name='profile'),
    path('join_webinar/', views.join_webinar, name='join_webinar'),
    path('webinars/<int:webinar_id>/register/', views.register_webinar, name='register_webinar'),
    path('webinars/', views.webinar_list, name='webinar_list'),
    path('my-registrations/', views.my_registrations, name='my_registrations'),
    path('webinar/<int:webinar_id>/registered-users/', views.webinar_registered_users, name='webinar_registered_users'),
    path('change_password/', views.change_password, name='change_password'),
    path('delete_webinar/<int:webinar_id>/', views.delete_webinar, name='delete_webinar'),
    path('admin_delete_webinar/<int:webinar_id>/', views.admin_delete_webinar, name='admin_delete_webinar'),
    path('create_announcement/', views.create_announcement, name='create_announcement'),
    path('feedback/<int:webinar_id>/', views.feedback_form, name='feedback_form'),
    path('select_webinar/', views.select_webinar, name='select_webinar'),
    path('select_hosted_webinars/', views.select_hosted_webinars, name='select_hosted_webinars'),
    path('webinars/<int:webinar_id>/feedback/', views.view_feedback, name='view_feedback'),
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('delete_announcements/<int:announcement_id>/', views.delete_announcements, name='delete_announcements'),
]