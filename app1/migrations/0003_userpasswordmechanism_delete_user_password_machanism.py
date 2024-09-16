# Generated by Django 5.1 on 2024-08-28 11:47

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0002_user_password_machanism'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserPasswordMechanism',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password_reset_token', models.CharField(blank=True, max_length=100)),
                ('password_reset_token_created', models.DateTimeField(null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='password_mechanism', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.DeleteModel(
            name='User_password_machanism',
        ),
    ]
