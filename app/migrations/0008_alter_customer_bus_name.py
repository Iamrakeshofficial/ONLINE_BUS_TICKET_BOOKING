# Generated by Django 4.1 on 2022-11-30 05:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0007_alter_customer_bus_name_alter_customer_sex'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customer',
            name='bus_name',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
