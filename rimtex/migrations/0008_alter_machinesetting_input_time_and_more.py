# Generated by Django 5.1.2 on 2024-11-04 07:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rimtex', '0007_alter_machinesetting_input_time_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='machinesetting',
            name='input_time',
            field=models.TimeField(null=True),
        ),
        migrations.AlterField(
            model_name='machinesetting',
            name='input_tolerance',
            field=models.TimeField(null=True),
        ),
        migrations.AlterField(
            model_name='machinesetting',
            name='output_time',
            field=models.TimeField(null=True),
        ),
        migrations.AlterField(
            model_name='machinesetting',
            name='output_tolerance',
            field=models.TimeField(null=True),
        ),
    ]
