# Generated by Django 5.0.1 on 2024-03-24 19:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webinars', '0003_remove_teacher_user_delete_student_delete_teacher'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='role',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]
