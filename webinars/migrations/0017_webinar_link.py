# Generated by Django 5.0.1 on 2024-04-06 07:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webinars', '0016_remove_webinar_link'),
    ]

    operations = [
        migrations.AddField(
            model_name='webinar',
            name='link',
            field=models.CharField(blank=True, default='', max_length=100),
        ),
    ]
