# Generated by Django 5.0.1 on 2024-03-29 11:55

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webinars', '0008_announcement'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Feedback',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('content_rating', models.IntegerField()),
                ('presentation_rating', models.IntegerField()),
                ('interactivity_rating', models.IntegerField()),
                ('overall_rating', models.IntegerField()),
                ('comments', models.TextField()),
                ('submitted_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('webinar', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='webinars.webinar')),
            ],
        ),
    ]
