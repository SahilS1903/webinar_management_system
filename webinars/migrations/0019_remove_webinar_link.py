# Generated by Django 5.0.1 on 2024-04-06 07:21

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('webinars', '0018_alter_webinar_link'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='webinar',
            name='link',
        ),
    ]
