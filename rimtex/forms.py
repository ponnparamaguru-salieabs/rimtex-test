from django import forms
from django.contrib.auth.models import User
from .models import MillLayout, MillLine

class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)
    phone = forms.CharField(max_length=20, required=False)
    role = forms.ChoiceField(choices=[('Maintenance', 'Maintenance'), ('Supervisor', 'Supervisor'), ('Operator', 'Operator')])
    permissions = forms.MultipleChoiceField(
    choices=[
        ('permissions_setup_machine_view', 'View Setup Machines'),
        ('permissions_setup_machine_edit', 'Edit Setup Machines'),
        ('permissions_set_shift_view', 'View Shift Settings'),
        ('permissions_set_shift_edit', 'Edit Shift Settings'),
        ('permissions_mill_layout_view', 'View Mill Layout'),
        ('permissions_mill_layout_edit', 'Edit Mill Layout'),
        ('permissions_line_config_view', 'View Line Configuration'),
        ('permissions_line_config_edit', 'Edit Line Configuration'),
        ('permissions_red_flag_view', 'View Red Flagging'),
        ('permissions_red_flag_edit', 'Edit Red Flagging'),
        ('permissions_can_manage_view', 'View Can Management'),
        ('permissions_can_manage_edit', 'Edit Can Management'),
        ('permissions_non_scan_view', 'View Non Scan Settings'),
        ('permissions_non_scan_edit', 'Edit Non Scan Settings'),
        ('permissions_reports_view', 'View Reports'),
    ],
    required=False, widget=forms.CheckboxSelectMultiple)

    class Meta:
        model = User
        fields = ['username', 'email']

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password != confirm_password:
            raise forms.ValidationError("Passwords do not match")
        return cleaned_data

class MillLayoutForm(forms.ModelForm):
    class Meta:
        model = MillLayout
        fields = ['layout_data']

class MillLineForm(forms.ModelForm):
    class Meta:
        model = MillLine
        fields = ['name', 'description', 'start_date', 'end_date', 'layout_data', 'machine_types']
        widgets = {
            'machine_types': forms.CheckboxSelectMultiple(),
        }