# Generated by Django 4.0.3 on 2022-12-12 13:14

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0019_alter_busdetails_destination_one_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='busdetails',
            name='destination_one',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='dest_loc', to='app.destination'),
        ),
        migrations.AlterField(
            model_name='busdetails',
            name='source',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='source_loc', to='app.destination'),
        ),
    ]
