# Generated by Django 3.2.9 on 2021-11-27 16:28

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('consumer', '0005_auto_20211127_2150'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='serversite',
            name='default',
        )
    ]
