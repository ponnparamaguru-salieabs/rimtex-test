# Generated by Django 5.1.2 on 2024-11-04 06:28

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rimtex', '0004_alter_millline_layout_data'),
    ]

    operations = [
        migrations.CreateModel(
            name='MachineSetting',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('input_time', models.TimeField()),
                ('input_tolerance', models.TimeField()),
                ('output_time', models.TimeField()),
                ('output_tolerance', models.TimeField()),
                ('machine', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rimtex.millmachine')),
            ],
        ),
    ]