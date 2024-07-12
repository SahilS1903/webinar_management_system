from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=50, blank=True, null=True)
    address = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    phone = models.CharField(max_length=15)
    dob = models.DateField(null=True, blank=True)
    status = models.BooleanField(default=False)
    GENDER_CHOICES = (
        ('M', 'Male'),
        ('F', 'Female'),
    )
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    bio = models.TextField(max_length=500, blank=True)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)

    def __str__(self):
        return str(self.user)

class CustomUser(User):
    class Meta:
        proxy = True

    def delete(self, *args, **kwargs):
        self.profile.delete()  # Delete associated profile
        super().delete(*args, **kwargs)  # Call superclass's delete method

User = CustomUser

class Webinar(models.Model):
    title = models.CharField(max_length=100)
    


    description = models.TextField()
    date = models.DateField()
    start_time = models.TimeField()
    duration_hours = models.IntegerField()
    end_time = models.TimeField()
    host = models.ForeignKey(User, on_delete=models.CASCADE, related_name='hosted_webinars')
    registrations = models.IntegerField(default=0)  # New field for registrations

    def __str__(self):
        return self.title
    
    def update_registrations_count(self):
        self.registrations = self.registration_set.count()
        self.save()

class Registration(models.Model):
    webinar = models.ForeignKey(Webinar, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def save(self, *args, **kwargs):
        if not self.pk:  # If the registration is being created (not updated)
            self.webinar.registrations += 1  # Increment registrations count
            self.webinar.save()  # Save the webinar object to reflect the change in registrations count
        super().save(*args, **kwargs)

from django.db import models
from django.utils import timezone

class Announcement(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


from django.db import models
from django.contrib.auth.models import User

class Feedback(models.Model):
    webinar = models.ForeignKey(Webinar, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content_rating = models.IntegerField()
    presentation_rating = models.IntegerField()
    interactivity_rating = models.IntegerField()
    overall_rating = models.IntegerField()
    comments = models.TextField()
    submitted_at = models.DateTimeField(auto_now_add=True)

    # Other fields and methods...
