# Generated by Django 5.0.1 on 2024-03-24 16:22

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('webinars', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='teacher',
            name='salary',
        ),
    ]
