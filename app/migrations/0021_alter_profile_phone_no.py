# Generated by Django 4.0.3 on 2022-12-13 04:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0020_alter_busdetails_destination_one_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='phone_no',
            field=models.CharField(max_length=13, null=True),
        ),
    ]
