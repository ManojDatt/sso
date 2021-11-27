# Generated by Django 3.2.9 on 2021-11-27 16:20

import django.contrib.sites.models
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('sites', '0002_alter_domain_unique'),
        ('consumer', '0004_auto_20211127_2130'),
    ]

    operations = [
        migrations.CreateModel(
            name='ServerSite',
            fields=[
                ('site_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='sites.site')),
                ('default', models.BooleanField(default=True)),
            ],
            bases=('sites.site',),
            managers=[
                ('objects', django.contrib.sites.models.SiteManager()),
            ],
        )
    ]
