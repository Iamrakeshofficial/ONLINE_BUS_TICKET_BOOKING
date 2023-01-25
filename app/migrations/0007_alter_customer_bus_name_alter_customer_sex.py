# Generated by Django 4.1 on 2022-11-30 05:45

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0006_remove_contact_address_remove_contact_name_manager_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customer',
            name='bus_name',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='app.busdetails'),
        ),
        migrations.AlterField(
            model_name='customer',
            name='sex',
            field=models.CharField(choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], max_length=200),
        ),
    ]
