from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required,  user_passes_test
from django.contrib.auth.hashers import make_password
from django.contrib.auth import login as auth_login, authenticate
from django.contrib import messages
from django.contrib.auth.models import User
from django.db.models import Q
from django.core.serializers import serialize
from django.http import JsonResponse, HttpResponseForbidden
from django.core.files.storage import default_storage
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from .forms import UserForm, MillLayoutForm
from .models import UserProfile, Machine, Mill, MillMachine, MillInfo, MillShift, MillLayout, MillLine, SetupMachine, MachineType, MachineSetting, MachineOverride, MachineConnectionLog, MachineStoppage,Log
from .decorators import role_required, permission_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from datetime import datetime
import json
import uuid
import paho.mqtt.client as mqtt
import logging
import threading
import os
from django.conf import settings
from .utils import create_log

def is_superuser(user):
    return user.is_superuser

def is_staff(user):
    return user.is_staff

def login_view(request):
    error = None
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            if user.is_superuser:
                return redirect('machineList')
            else:
                return redirect('dashboard')
        else:
            error_message = 'Invalid username or password.'
            messages.error(request, error_message)
            error = error_message

    return render(request, 'login.html', {'error': error})

# Machine List View
@login_required
@user_passes_test(is_superuser)
def machineList(request):
    machines = Machine.objects.all()
    return render(request, 'machine_list.html', {
        'machines': machines,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Machines', 'url': '#'}
        ],
        'active_menu': 'machine'
    })

@login_required
@user_passes_test(is_superuser)
def machineAdd(request):
    if request.method == 'POST':
        type = request.POST.get('type')
        code = request.POST.get('code')
        model = request.POST.get('model')
        make_year = request.POST.get('make_year')
        design = request.POST.get('design')
        manufacturer = request.POST.get('manufacturer')
        num_inputs = request.POST.get('num_inputs')
        num_outputs = request.POST.get('num_outputs')
        image = request.POST.get('image')  
        status = 'status' in request.POST

        machine = Machine(
            type=type,
            code=code,
            model=model,
            make_year=make_year,
            design=design,
            manufacturer=manufacturer,
            num_inputs=num_inputs,
            num_outputs=num_outputs,
            image=image,
            status=status
        )
        machine.save()
        create_log('ADD', 'Machine', machine.id, request.user, f"Added machine with code {code}")
        messages.success(request, 'Machine added successfully')
        return redirect('machineList')
    
    return render(request, 'machine_add.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Machines', 'url': '/machine-list'},
            {'name': 'Add Machine', 'url': '/machine-add'}
        ],
        'active_menu': 'machine'})

def file_upload(request):
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        file_name = default_storage.save('machine_images/' + uploaded_file.name, uploaded_file)
        file_url = default_storage.url(file_name)
        
        relative_file_url = file_url.replace('/media/', '')

        return JsonResponse({'fileUrl': relative_file_url})
    return JsonResponse({'error': 'Invalid request'}, status=400)

@login_required
@user_passes_test(is_superuser)
def machineEdit(request, id):    
    machine = get_object_or_404(Machine, id=id)

    if request.method == 'POST':
        machine.type = request.POST.get('type')
        machine.code = request.POST.get('code')
        machine.model = request.POST.get('model')
        machine.make_year = request.POST.get('make_year')
        machine.design = request.POST.get('design')
        machine.manufacturer = request.POST.get('manufacturer')
        machine.num_inputs = request.POST.get('num_inputs')
        machine.num_outputs = request.POST.get('num_outputs')
        machine.status = 'status' in request.POST

        if request.POST.get('image'):
            machine.image = request.POST.get('image')

        machine.save()
        create_log('EDIT', 'Machine', machine.id, request.user, f"Edited machine with code {machine.code}")

        return redirect('machineList') 
    
    return render(request, 'machine_edit.html', {
        'machine': machine,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Machines', 'url': '#'},
            {'name': 'Edit Machine', 'url': '#'}
        ],
        'active_menu': 'machine'
    })

@login_required
@user_passes_test(is_superuser)
def machineDelete(request, id):
    if request.method == 'POST':
        machine = get_object_or_404(Machine, id=id)
        machine.delete()
        create_log('DELETE', 'Machine', id, request.user, f"Deleted machine with code {machine.code}")
        return JsonResponse({'success': True})
    return render(request, 'machine_delete_confirm.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Machines', 'url': '/machine-list'},
            {'name': 'Delete Machine', 'url': f'/machine-delete/{id}'}
        ],
        'active_menu': 'machine'
    })

@login_required
@user_passes_test(is_superuser)
def userList(request):
    users = User.objects.filter(is_staff=True, is_superuser=False)
    return render(request, 'user_list.html', {
        'users': users,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'User Management', 'url': '/user-list'},
        ],
        'active_menu': 'user'
    })

@login_required
@user_passes_test(is_superuser)
def userAdd(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        phone = request.POST.get('phone')

        if len(username) < 2:
            messages.error(request, 'Username must be at least 2 characters long.')
            return redirect('userAdd')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return redirect('userAdd')

        if not email or '@' not in email:
            messages.error(request, 'Please enter a valid email address.')
            return redirect('userAdd')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('userAdd')

        if len(password) < 6:
            messages.error(request, 'Password must be at least 6 characters long.')
            return redirect('userAdd')

        mill_id = str(uuid.uuid4())
        mill = Mill.objects.create(mill_id=mill_id)

        user = User.objects.create(
            username=username,
            email=email,
            password=make_password(password),
            is_staff=True
        )

        user_profile, created = UserProfile.objects.get_or_create(user=user)

        user_profile.mill = mill
        user_profile.phone = phone
        user_profile.role = 'Admin'
        user_profile.save()

        machine_types = [
            'Carding',
            'Breaker',
            'Unilap',
            'Comber',
            'Finisher',
            'Roving'
        ]

        for machine_name in machine_types:
            machine_type, created = MachineType.objects.get_or_create(
                type=machine_name
            )
            mill.machine_types.add(machine_type)
        
        create_log('ADD', 'User', user.id, request.user, f"Added user {username}")

        messages.success(request, 'Mill and admin user created successfully!')
        return redirect('userList')

    return render(request, 'user_add.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'User Management', 'url': '/user-list'},
            {'name': 'Add User', 'url': '/user-add'}
        ],
        'active_menu': 'user',
    })

@login_required
@user_passes_test(is_superuser)
def userEdit(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user_profile = get_object_or_404(UserProfile, user=user)

    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        phone = request.POST.get('phone')

        if len(username) < 2:
            messages.error(request, 'Username must be at least 2 characters long.')
            return redirect('userEdit', user_id=user.id)

        if User.objects.exclude(id=user.id).filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return redirect('userEdit', user_id=user.id)

        if not email or '@' not in email:
            messages.error(request, 'Please enter a valid email address.')
            return redirect('userEdit', user_id=user.id)

        if password and password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('userEdit', user_id=user.id)
        
        user.username = username
        user.email = email

        if password:
            user.password = make_password(password)
        user.save()

        user_profile.phone = phone
        user_profile.save()
        create_log('EDIT', 'User', user.id, request.user, f"Edited user {username}")

        messages.success(request, 'User updated successfully!')
        return redirect('userList')

    return render(request, 'user_edit.html', {
        'user': user,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'User Management', 'url': '/user-list'},
            {'name': 'Edit User', 'url': f'/mill-user-edit/{user.id}'}
        ],
        'active_menu': 'user',
    })

@login_required
@user_passes_test(is_superuser)
def userDelete(request, pk):
    if request.method == 'POST':
        user = get_object_or_404(User, pk=pk)
        create_log('DELETE', 'User', user.id, request.user, f"Deleted user {user.username}")
        user.delete()

        messages.success(request, 'User deleted successfully.')
        return redirect('userList')

    user = get_object_or_404(User, pk=pk)
    return render(request, 'user_delete_confirm.html', {
        'user': user,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'User Management', 'url': '/user-list'},
            {'name': 'Delete User', 'url': f'/user-delete/{pk}'}
        ],
        'active_menu': 'user'
    })


@login_required
@user_passes_test(is_superuser)
def logList(request):
    logs = Log.objects.all().order_by('-timestamp')
    return render(request, 'logs.html', {
        'logs': logs,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Log List', 'url': '/logs'},
        ],
        'active_menu': 'settings',
    })


# Mill Info View
@login_required
@role_required(['Admin'])
def millUserList(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill

    users = User.objects.filter(is_staff=False, userprofile__mill=mill)

    return render(request, 'mill_user_list.html', {
        'users': users,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Mill Users', 'url': '/mill_user_list'},
        ],
        'active_menu': 'millUser',
        'mill':mill
    })

# Add User View
@login_required
@role_required(['Admin'])
def millUserAdd(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password')
            phone = form.cleaned_data.get('phone')
            role = form.cleaned_data.get('role')

            user_profile = UserProfile.objects.get(user=request.user)
            mill = user_profile.mill

            print(mill.id) 

            permissions = {
                'setup_machine_view': request.POST.get('permissions_setup_machine_view') == 'on',
                'setup_machine_edit': request.POST.get('permissions_setup_machine_edit') == 'on',
                'set_shift_view': request.POST.get('permissions_set_shift_view') == 'on',
                'set_shift_edit': request.POST.get('permissions_set_shift_edit') == 'on',
                'mill_layout_view': request.POST.get('permissions_mill_layout_view') == 'on',
                'mill_layout_edit': request.POST.get('permissions_mill_layout_edit') == 'on',
                'line_config_view': request.POST.get('permissions_line_config_view') == 'on',
                'line_config_edit': request.POST.get('permissions_line_config_edit') == 'on',
                'red_flag_view': request.POST.get('permissions_red_flag_view') == 'on',
                'red_flag_edit': request.POST.get('permissions_red_flag_edit') == 'on',
                'can_manage_view': request.POST.get('permissions_can_manage_view') == 'on',
                'can_manage_edit': request.POST.get('permissions_can_manage_edit') == 'on',
                'non_scan_view': request.POST.get('permissions_non_scan_view') == 'on',
                'non_scan_edit': request.POST.get('permissions_non_scan_edit') == 'on',
                'reports_view': request.POST.get('permissions_reports_view') == 'on',
            }

            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists.')
                return redirect('millUserAdd')

            user = User.objects.create(
                username=username,
                email=email,
                password=make_password(password),
                is_staff=False
            )

            user_profile, created = UserProfile.objects.get_or_create(
                user=user,
                defaults={
                    'phone': phone,
                    'role': role,
                    'permissions': permissions,
                    'mill': mill
                }
            )

            if not created:
                user_profile.phone = phone
                user_profile.role = role
                user_profile.permissions = permissions
                user_profile.mill = mill  
                user_profile.save()

            messages.success(request, 'User added/updated successfully!')
            return redirect('millUserList')
        else:
            for field in form:
                for error in field.errors:
                    print(f"Error in {field.name}: {error}")
            messages.error(request, 'Please correct the errors below.')

    else:
        form = UserForm()

    return render(request, 'mill_user_add.html', {
        'form': form,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'User Management', 'url': '/user-list'},
            {'name': 'Add Mill User', 'url': '/mill-user-add'}
        ],
        'active_menu': 'millUser',
        'mill':mill
    })

@login_required
@role_required(['Admin'])
def millUserEdit(request, pk):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill

    user = get_object_or_404(User, id=pk)
    profile, created = UserProfile.objects.get_or_create(user=user)
    
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        role = request.POST.get('role')
        permissions = {
                'setup_machine_view': request.POST.get('permissions_setup_machine_view') == 'on',
                'setup_machine_edit': request.POST.get('permissions_setup_machine_edit') == 'on',
                'set_shift_view': request.POST.get('permissions_set_shift_view') == 'on',
                'set_shift_edit': request.POST.get('permissions_set_shift_edit') == 'on',
                'mill_layout_view': request.POST.get('permissions_mill_layout_view') == 'on',
                'mill_layout_edit': request.POST.get('permissions_mill_layout_edit') == 'on',
                'line_config_view': request.POST.get('permissions_line_config_view') == 'on',
                'line_config_edit': request.POST.get('permissions_line_config_edit') == 'on',
                'red_flag_view': request.POST.get('permissions_red_flag_view') == 'on',
                'red_flag_edit': request.POST.get('permissions_red_flag_edit') == 'on',
                'can_manage_view': request.POST.get('permissions_can_manage_view') == 'on',
                'can_manage_edit': request.POST.get('permissions_can_manage_edit') == 'on',
                'non_scan_view': request.POST.get('permissions_non_scan_view') == 'on',
                'non_scan_edit': request.POST.get('permissions_non_scan_edit') == 'on',
                'reports_view': request.POST.get('permissions_reports_view') == 'on',
        }

        if password and password == confirm_password:
            user.password = make_password(password)
        
        user.username = username
        user.email = email
        user.save()
        
        profile.phone = phone
        profile.role = role
        profile.permissions = permissions
        profile.save()

        messages.success(request, 'User updated successfully')
        return redirect('millUserList')

    context = {
        'user': user,
        'profile': profile,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'User Management', 'url': '/mill-user-list'},
            {'name': 'Edit User', 'url': f'/mill-user-edit/{pk}'}
        ],
        'active_menu': 'millUser',
        'mill':mill
    }

    return render(request, 'mill_user_edit.html', context)

# Delete User View
@login_required
@role_required(['Admin'])
def millUserDelete(request, pk):
    if request.method == 'POST':
        user = get_object_or_404(User, pk=pk)
        user.delete()
        messages.success(request, 'User deleted successfully.')
        return redirect('millUserList')

    user = get_object_or_404(User, pk=pk)
    return render(request, 'user_delete_confirm.html', {
        'user': user,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'User Management', 'url': '/user-list'},
            {'name': 'Delete User', 'url': f'/user-delete/{pk}'}
        ],
        'active_menu': 'user'
    })

from collections import defaultdict
from django.db.models import Sum
from decimal import Decimal
from datetime import timedelta
import pytz

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
def dashboard(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    lines = MillLine.objects.filter(mill=mill)
    mill_id = mill.id
    overrides = MachineOverride.objects.filter(mill_id=mill_id)
    stoppages = MachineStoppage.objects.filter(mill_id=mill_id)
    selected_line_id = request.GET.get('line_id')    
    if selected_line_id:
        try:
            selected_line = MillLine.objects.get(id=selected_line_id)
        except MillLine.DoesNotExist:
            selected_line = None
    else:
        selected_line = lines.first()
    if selected_line is None:
        selected_line = MillLine()  
        selected_line_id = None   
    overrides = overrides.filter(line_id=selected_line.id)
    stoppages = stoppages.filter(line_id=selected_line.id)
    override_data = {
        'Carding': 0,
        'Breaker': 0,
        'Unilap': 0,
        'Comber': 0,
        'Finisher': 0,
        'Rover': 0
    }
    for override in overrides:
        if override.device_type in override_data:
            override_data[override.device_type] += override.count
    chart_data = {
        'labels': list(override_data.keys()),
        'series': list(override_data.values())
    }
    chart_data_json = json.dumps(chart_data)
    stoppage_data = {
        'Carding': 0,
        'Breaker': 0,
        'Unilap': 0,
        'Comber': 0,
        'Finisher': 0,
        'Rover': 0
    }
    for stoppage in stoppages:
        if stoppage.device_type in stoppage_data:
            stoppage_data[stoppage.device_type] += stoppage.count

    stoppage_chart_data = {
        'labels': list(stoppage_data.keys()),
        'series': list(stoppage_data.values())
    }
    stoppage_chart_data_json = json.dumps(stoppage_chart_data)
    machine_types = ['Carding', 'Breaker', 'Unilap', 'Comber', 'Finisher', 'Rover']
    machine_time_ranges = {
        'Carding': {'>24': 0, '16-24': 0, '8-16': 0, '0-8': 0},
        'Breaker': {'>24': 0, '16-24': 0, '8-16': 0, '0-8': 0},
        'Unilap': {'>24': 0, '16-24': 0, '8-16': 0, '0-8': 0},
        'Comber': {'>24': 0, '16-24': 0, '8-16': 0, '0-8': 0},
        'Finisher': {'>24': 0, '16-24': 0, '8-16': 0, '0-8': 0},
        'Rover': {'>24': 0, '16-24': 0, '8-16': 0, '0-8': 0}
    }

    logs = MachineConnectionLog.objects.filter(
        line_id=selected_line.id,
        output_machine__in=machine_types,
        output_time__isnull=False,
        input_machine__isnull=True,
        input_time__isnull=True
    )

    now_utc = timezone.now()
    ist = pytz.timezone('Asia/Kolkata')
    now_ist = now_utc.astimezone(ist)

    for log in logs:
        time_difference = (now_ist - log.output_time).total_seconds() / 3600
        machine_type = log.output_machine
        if time_difference > 24:
            machine_time_ranges[machine_type]['>24'] += 1
        elif 16 <= time_difference <= 24:
            machine_time_ranges[machine_type]['16-24'] += 1
        elif 8 <= time_difference < 16:
            machine_time_ranges[machine_type]['8-16'] += 1
        elif 0 <= time_difference < 8:
            machine_time_ranges[machine_type]['0-8'] += 1

    machine_time_ranges_json = json.dumps(machine_time_ranges)
    v_chart_data = {
        'labels': machine_types,
        'series': [sum([machine_time_ranges[machine][range_] for range_ in machine_time_ranges[machine]]) for machine in machine_types]
    }
    v_chart_data_json = json.dumps(v_chart_data)
    unloading_details_sum = MillMachine.objects.filter(
        line_id=selected_line.id,
    ).values('type').annotate(
        total_unloading_details_kg=Sum('unloading_details_kg')
    )

    unloading_details_dict = {
        'Carding': 0.0,
        'Breaker': 0.0,
        'Unilap': 0.0,
        'Comber': 0.0,
        'Finisher': 0.0,
        'Roving': 0.0,
    }

    for item in unloading_details_sum:
        unloading_details_dict[item['type']] = float(item['total_unloading_details_kg'] or 0)
    unloading_details_dict_json = json.dumps(unloading_details_dict)
    start_date = selected_line.start_date if selected_line.start_date else None
    end_date = selected_line.end_date if selected_line.end_date else None
    
    if start_date and end_date:
        total_duration = (end_date - start_date).total_seconds()
        elapsed_time = (now_ist - start_date).total_seconds()
        total_duration = round(total_duration / 3600, 2)
        elapsed_time = round(elapsed_time / 3600, 2)

        lineProgress_data = {
            'total_duration': total_duration,
            'elapsed_time': elapsed_time,
        }
        lineProgress_json = json.dumps(lineProgress_data)
    else:
        lineProgress_json = json.dumps({'total_duration': 0, 'elapsed_time': 0})
    machine_time_max = {machine: 0 for machine in machine_types}
    for log in logs:
        time_difference = (now_ist - log.output_time).total_seconds() / 3600
        machine_type = log.output_machine
        if machine_type in machine_time_max:
            machine_time_max[machine_type] = max(machine_time_max[machine_type], time_difference)
    machine_time_display = {}
    machine_stoppage_duration = {}
    for machine, max_hours in machine_time_max.items():
        total_minutes = int(max_hours * 60)
        machine_stoppage_duration[machine] = total_minutes
        hours = int(max_hours)
        minutes = int((max_hours - hours) * 60)
        machine_time_display[machine] = f"{hours}h {minutes}m"
    machine_time_display_json = json.dumps(machine_time_display)
    machine_stoppage_duration_json = json.dumps(machine_stoppage_duration)
    # print(machine_stoppage_duration_json)
    return render(request, 'dashboard.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Dashboard', 'url': ''},
        ],
        'mill': mill,
        'lines': lines,
        'active_menu': 'dashboard',
        'selected_line': selected_line,
        'chart_data_json': chart_data_json,
        'v_chart_data_json': v_chart_data_json,
        'unloading_details_dict_json': unloading_details_dict_json,
        'stoppage_chart_data_json': stoppage_chart_data_json,
        'machine_time_ranges_json': machine_time_ranges_json,
        'lineProgress_json': lineProgress_json,
        'machine_time_display_json': machine_time_display_json,
        'machine_stoppage_duration_json' : machine_stoppage_duration_json
    })

def get_machine_models(request):
    machine_type = request.GET.get('type')
    machines = Machine.objects.filter(type=machine_type, status=True).values(
        'id', 'code', 'model', 'make_year', 'design', 'manufacturer', 
        'num_inputs', 'num_outputs', 'image', 'status'
    )
    print(machines) 
    return JsonResponse(list(machines), safe=False)

@login_required
@role_required(['Admin', 'Manager', 'Supervisor'])
@permission_required(['mill_config_edit'])
@csrf_exempt  
def add_machine(request):
    if request.method == 'POST':
        machine_type = request.POST.get('machine_type')
        machine_model = request.POST.get('machine_model')
        machine_code = request.POST.get('machine_code')
        manufacturer = request.POST.get('manufacturer')
        num_machines = request.POST.get('num_machines')
        num_starting = request.POST.get('num_starting', 1)
        design = request.POST.get('design', 0)
        make_year = request.POST.get('make_year', 0)
        num_inputs = request.POST.get('num_inputs', 0)
        num_outputs = request.POST.get('num_outputs', 0)
        image = request.POST.get('image')
        user_profile = UserProfile.objects.get(user=request.user)
        mill = user_profile.mill
        if not machine_type or not machine_model or not num_machines:
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        try:
            num_machines = int(num_machines)
            num_starting = int(num_starting)
        except ValueError:
            return JsonResponse({'error': 'Invalid number format'}, status=400)
        for i in range(num_machines):
            name = f"{machine_type} {str(num_starting + i).zfill(3)}"
            mill_machine = MillMachine(
                type=machine_type,
                code=machine_code,
                model=machine_model,
                make_year=make_year,
                design=design,
                manufacturer=manufacturer,
                num_inputs=num_inputs,
                num_outputs=num_outputs,
                image=image,
                machine_name=name,
                mill = mill
            )
            mill_machine.save()
        return JsonResponse({'message': 'Machines added successfully!'}, status=201)
    return JsonResponse({'error': 'Invalid request'}, status=400)

@login_required
@role_required(['Admin', 'Manager', 'Supervisor'])
@permission_required(['mill_config_edit'])
@csrf_exempt
def update_machine(request, machine_id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            new_name = data.get('new_name')

            if not new_name:
                return JsonResponse({'error': 'New name is required'}, status=400)
            
            mill_machine = MillMachine.objects.get(id=machine_id)
            mill_machine.machine_name = new_name
            mill_machine.save()
            return JsonResponse({'message': 'Machine name updated successfully!'}, status=200)

        except MillMachine.DoesNotExist:
            return JsonResponse({'error': 'Machine not found'}, status=404)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

    return JsonResponse({'error': 'Invalid request'}, status=400)

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['mill_config_edit'])
@csrf_exempt
def delete_machine(request, machine_id):
    if request.method == 'POST':
        try:
            machine = MillMachine.objects.get(id=machine_id)
            machine.delete()
            return JsonResponse({'message': 'Machine deleted successfully!'}, status=200)
        except MillMachine.DoesNotExist:
            return JsonResponse({'error': 'Machine not found'}, status=404)
    return JsonResponse({'error': 'Invalid request'}, status=400)

# Mill Config View
@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['mill_config_edit'])
def millConfig(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    
    machines = Machine.objects.filter(status=True).values('code', 'model', 'type')
    mill_machines = MillMachine.objects.filter(mill=mill)
    machine_type = SetupMachine.objects.filter(is_add=True, mill=mill)
    
    return render(request, 'mill_config.html', {
        'machines': machines,
        'machine_type': machine_type,
        'mill_machines': mill_machines,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Mill Configuration', 'url': ''},
        ],
        'active_menu': 'millConfig',
        'mill': mill
    })

def check_machine_exists(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    if request.method == 'GET':
        machine_type = request.GET.get('machine_type')
        num_machines = int(request.GET.get('num_machines'))
        starting_number = int(request.GET.get('starting_number'))

        duplicates = []
        for i in range(starting_number, starting_number + num_machines):
            machine_name = f"{machine_type} {i:03d}"
            if MillMachine.objects.filter(machine_name=machine_name, mill=mill).exists():
                duplicates.append(machine_name)

        return JsonResponse({'duplicates': duplicates})

def check_machine_name(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    if request.method == 'GET':
        machine_name = request.GET.get('machine_name')
        exclude_id = request.GET.get('exclude_id') 
        exists = MillMachine.objects.filter(machine_name=machine_name,mill=mill).exclude(id=exclude_id).exists()
        return JsonResponse({'exists': exists})

def millSetupMachine(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    machines = SetupMachine.objects.filter(mill=mill)
    if request.method == 'POST':
        for machine in machines:
            checkbox_name = f"machine_{machine.id}"
            if checkbox_name in request.POST:
                machine.is_add = True  
            else:
                machine.is_add = False
            machine.save()
        return redirect('millConfig')
    return render(request, 'mill_setup_machines.html', {
        'machines': machines,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Mill Setup', 'url': ''},
        ],
        'active_menu': 'millConfig',
        'mill': mill
    })

def update_machines(request):
    if request.method == 'POST':
        for machine in SetupMachine.objects.all():
            checkbox_name = f"machine_{machine.id}"
            if checkbox_name in request.POST:
                machine.is_add = True  
            else:
                machine.is_add = False  
            machine.save()
        return redirect('millConfig') 
    return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)

@login_required
@role_required(['Admin'])
def millInfo(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill   
    mill_info, created_info = MillInfo.objects.get_or_create(mill=mill)

    if request.method == 'POST':
        name = request.POST.get('name', '') 
        unit_number = request.POST.get('unit_number', '')
        phone = request.POST.get('phone', '')
        email = request.POST.get('email', '')
        logo = request.POST.get('logo')  

        mill_info.name = name
        mill_info.unit_number = unit_number
        mill_info.phone = phone
        mill_info.email = email

        if logo:
            mill_info.logo = logo 

        mill_info.save()
        return redirect('millSetupMachine')

    return render(request, 'mill_info.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Mill Information', 'url': ''},
        ],
        'active_menu': 'millConfig',
        'mill_info': mill_info,
        'mill':mill
    })

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['set_shift_view'])
def millShift(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill  
    shifts = MillShift.objects.filter(mill=mill)
    shifts_data = serialize('json', shifts)

    if request.method == "POST":
        action = request.POST.get('action')  
        shift_id = request.POST.get('shift_id')

        if action == 'delete' and shift_id:  
            try:
                shift = get_object_or_404(MillShift, id=shift_id)
                shift.delete()
            except Exception as e:
                print(f"Error deleting shift: {e}")
            return redirect('millShift')

        shift_name = request.POST.get('shift_name')
        start_time = request.POST.get('start_time')
        end_time = request.POST.get('end_time')

        def parse_time(time_str):
            try:
                return timezone.datetime.strptime(time_str, '%H:%M:%S').time()
            except ValueError:
                return timezone.datetime.strptime(time_str, '%H:%M').time()

        try:
            start_datetime = parse_time(start_time)
            end_datetime = parse_time(end_time)
        except ValueError as e:
            print(f"Error parsing time: {e}")
            return render(request, 'mill_shift.html', {
                'shifts': shifts,
                'shifts_data': shifts_data,
                'error': 'Invalid time format. Please use HH:MM or HH:MM:SS format.',
                'breadcrumb': [
                    {'name': 'Home', 'url': ''},
                    {'name': 'Mill Shift', 'url': ''},
                ],
                'active_menu': 'millConfig',
                'mill': mill
            })

        if action == 'add': 
            MillShift.objects.create(
                mill=mill,
                shift_name=shift_name,
                start_time=start_datetime,
                end_time=end_datetime
            )
        elif action == 'edit' and shift_id: 
            shift = get_object_or_404(MillShift, id=shift_id)
            shift.shift_name = shift_name
            shift.start_time = start_datetime
            shift.end_time = end_datetime
            shift.save()

        return redirect('millShift')

    return render(request, 'mill_shift.html', {
        'shifts': shifts,
        'shifts_data': shifts_data,
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Mill Shift', 'url': ''},
        ],
        'active_menu': 'millConfig',
        'mill': mill
    })

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['mill_layout_view'])
def millLayout(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        mill = user_profile.mill

        if request.method == 'POST':
            data = json.loads(request.body)
            layout_data = data.get('layout_data')

            layout, created = MillLayout.objects.get_or_create(mill=mill)

            form = MillLayoutForm(instance=layout, data={'layout_data': layout_data})

            if form.is_valid():
                form.save()
                return JsonResponse({'status': 'success'})
            else:
                return JsonResponse({'status': 'error', 'errors': form.errors}, status=400)

        layout = MillLayout.objects.filter(mill=mill).first()
        layout_data = layout.layout_data if layout else {}

        return render(request, 'mill_layout.html', {
            'breadcrumb': [
                {'name': 'Home', 'url': ''},
                {'name': 'Mill Layout', 'url': ''},
            ],
            'active_menu': 'millLayout',
            'layout_data': json.dumps(layout_data),
            'mill': mill
        })
    
    except ObjectDoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'User profile not found'}, status=404)

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['line_config_view'])
def millLineDetails(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill

    if request.method == 'POST':
        line_name = request.POST.get('line_name')
        line_description = request.POST.get('line_description')

        mill_line = MillLine(
            name=line_name,
            description=line_description,
            layout_data={},
            mill=mill
        )
        mill_line.save()

        return redirect('millLineSelectPattern', line_id=mill_line.id)
    
    return render(request, 'line_details.html', {
        'breadcrumb': [
            {'name': 'Mill Line Configuration', 'url': ''},
        ],
        'active_menu': 'millLine',
        'mill': mill
    })

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['line_config_edit'])
def editMillLine(request, line_id):
    mill_line = get_object_or_404(MillLine, id=line_id)

    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    
    if mill_line.mill != mill:
        messages.error(request, "You do not have access to this mill line.")
        return redirect('millLine')
    
    if request.method == 'POST':
        line_name = request.POST.get('line_name')
        line_description = request.POST.get('line_description')

        mill_line.name = line_name
        mill_line.description = line_description
        mill_line.save()

        return redirect('millLineSelectPattern', line_id=mill_line.id)

    return render(request, 'line_details_edit.html', {
        'mill_line': mill_line,
        'breadcrumb': [
            {'name': 'Mill Line Configuration', 'url': ''},
        ],
        'line_id':line_id,
        'active_menu': 'millLine',
        'mill': mill
    })

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['line_config_edit'])
def millLineSelectPattern(request, line_id):
    mill_line = get_object_or_404(MillLine, id=line_id)
    
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill

    if mill_line.mill != mill:
        messages.error(request, "You do not have access to this mill line.")
        return redirect('millLine')

    if request.method == 'POST':
        selected_machine_types = request.POST.getlist('machine_types')
        mill_line.machine_types.clear()
        for machine_name in selected_machine_types:
            machine, created = MachineType.objects.get_or_create(type=machine_name)
            mill_line.machine_types.add(machine)

        messages.success(request, "Machine types updated successfully.")
        return redirect('millLineSelectMachine', line_id=mill_line.id)

    machine_types = mill.machine_types.all()

    return render(request, 'line_pattern.html', {
        'mill_line': mill_line,
        'machine_types': machine_types,
        'selected_machine_types': mill_line.machine_types.all(),
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Mill Report', 'url': ''},
        ],
        'active_menu': 'millLine',
        'line_id': line_id,
        'mill': mill
    })

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['line_config_edit'])
def millLineSelectMachine(request, line_id):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    mill_line = get_object_or_404(MillLine, id=line_id)
    if mill_line.mill != mill:
        messages.error(request, "You do not have access to this mill line.")
        return redirect('millLine')

    selected_machine_types = mill_line.machine_types.values_list('type', flat=True)
    filtered_machines = MillMachine.objects.filter(
        type__in=selected_machine_types,
        mill=mill
    ).filter(
        Q(line__isnull=True) | Q(line_id=line_id)
    )

    return render(request, 'line_select_machines.html', {
        'breadcrumb': [
            {'name': 'Mill Line Configuration', 'url': ''},
        ],
        'machine_types': MachineType.objects.all(),
        'filtered_machines': filtered_machines,
        'active_menu': 'millLine',
        'line_id': line_id,
        'mill': mill
    })

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['line_config_edit'])
@csrf_exempt
def save_loading_unloading_details(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        machine_ids = data.get('machine_ids', [])
        loading_detail_m = data.get('loading_detail_m')
        unloading_detail_m = data.get('unloading_detail_m')
        loading_detail_kg = data.get('loading_detail_kg')
        unloading_detail_kg = data.get('unloading_detail_kg')
        loading_time_mins = data.get('loading_time_mins')
        unloading_time_mins = data.get('unloading_time_mins')
        line_id = data.get('line_id')

        try:
            for machine_id in machine_ids:
                machine = MillMachine.objects.get(id=machine_id)
                machine.loading_details_m = loading_detail_m
                machine.unloading_details_m = unloading_detail_m
                machine.loading_details_kg = loading_detail_kg
                machine.unloading_details_kg = unloading_detail_kg
                machine.loading_time = loading_time_mins
                machine.unloading_time = unloading_time_mins
                machine.line_id = line_id 
                machine.save()

            return JsonResponse({'success': True})
        except MillMachine.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'One or more machines do not exist.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})

    return JsonResponse({'success': False, 'message': 'Invalid request method.'})

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['line_config_edit'])
def unassign_machine_line(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        machine_ids = data.get('machine_ids')
        if not machine_ids:
            return JsonResponse({'success': False, 'message': 'No machine IDs provided.'})
        try:
            machines = MillMachine.objects.filter(id__in=machine_ids)
            if not machines:
                return JsonResponse({'success': False, 'message': 'No machines found with the provided IDs.'})
            machines.update(
                line=None,
                is_assigned=False,
                loading_details_m=None,
                unloading_details_m=None,
                loading_details_kg=None,
                unloading_details_kg=None,
                loading_time=None,
                unloading_time=None
            )
            return JsonResponse({'success': True, 'message': 'Machines unassigned successfully!'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['line_config_edit'])
def millLineConfigLine(request, line_id):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    mill_line = get_object_or_404(MillLine, id=line_id)
    selected_machine_types = mill_line.machine_types.values_list('type', flat=True)
    filtered_machines = MillMachine.objects.filter(
        type__in=selected_machine_types
    ).filter(line_id=line_id)
    filtered_machines_data = list(filtered_machines.values(
        'id', 'machine_name', 'type', 'num_inputs', 'num_outputs', 'image'
    ))
    layout_data = mill_line.layout_data or {} 
    context = {
        'line_id': line_id,
        'filtered_machines_data': filtered_machines_data,
        'active_menu': 'millLine',
        'breadcrumb': [
            {'name': 'Mill Line Configuration', 'url': ''},
        ], 
        'layout_data': json.dumps(layout_data),
        'mill': mill
    }
    return render(request, 'line_config.html', context)

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['line_config_edit'])
@csrf_exempt
def save_line_layout(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            layout_data = data.get('layout_data')
            line_id = data.get('line_id')
            mill_line = get_object_or_404(MillLine, id=line_id)
            mill_line.layout_data = layout_data 
            mill_line.save()

            return JsonResponse({'success': True}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

from .mqtt import setup_mqtt
def millLine(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    lines = MillLine.objects.filter(mill=mill)
    started_lines = MillLine.objects.filter(mill=mill, is_start=True)

    all_device_ids = []
    formatted_connections_for_lines = []

    for line in started_lines:
        layout_data = line.layout_data
        formatted_connections, device_ids = format_layout_data(layout_data)
        formatted_connections_for_lines.append(formatted_connections)
        all_device_ids.extend(device_ids)

    all_device_ids = list(set(all_device_ids))
    setup_mqtt(all_device_ids, formatted_connections_for_lines, request)

    data_to_store = {
        'all_device_ids': all_device_ids,
        'formatted_connections_for_lines': formatted_connections_for_lines,
        'request': {
            'user': {
                'username': request.user.username,
                'email': request.user.email,
                'id': request.user.id,
            },
            'mill_id': mill.id,
            'method': request.method,
            'path': request.path,
            'GET': dict(request.GET),
            'POST': dict(request.POST),
        }
    }

    file_path = os.path.join(settings.BASE_DIR, 'mill_line_data.json')
    try:
        with open(file_path, 'w') as json_file:
            json.dump(data_to_store, json_file, indent=4)
        logger.info(f"Data successfully written to {file_path}")
    except Exception as e:
        logger.error(f"Error writing to JSON file: {e}")

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            line_id = data.get('line_id')
            stop = data.get('stop')
            start_date = data.get('start_date')
            end_date = data.get('end_date')
            logger.info(f"Received POST request to change line state: line_id={line_id}, stop={stop}, start_date={start_date}, end_date={end_date}")
            line = get_object_or_404(MillLine, id=line_id, mill=mill)

            if stop:
                line.is_start = False
                line.start_date = None
                line.end_date = None
                logger.info(f"Stopping line {line_id}")
            else:
                line.start_date = start_date
                line.end_date = end_date
                line.is_start = True
            line.save()
            
            return JsonResponse({'status': 'success'})
        except MillLine.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Line not found'})
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON data'})
        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            return JsonResponse({'status': 'error', 'message': 'An error occurred'})
    
    if request.method == "DELETE":
        try:
            data = json.loads(request.body)
            line_id = data.get('line_id')
            logger.info(f"Received DELETE request to remove line: line_id={line_id}")
            line = get_object_or_404(MillLine, id=line_id, mill=mill)
            machines = MillMachine.objects.filter(line=line)
            for machine in machines:
                machine.loading_time = None
                machine.unloading_time = None
                machine.loading_details_m = None
                machine.unloading_details_m = None
                machine.loading_details_kg = None
                machine.unloading_details_kg = None
                machine.save()
            line.delete()
            logger.info(f"Line {line_id} successfully deleted.")
            return JsonResponse({'status': 'success'})
        except MillLine.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Line not found'})
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON data'})
        except Exception as e:
            logger.error(f"Error handling DELETE request: {e}")
            return JsonResponse({'status': 'error', 'message': 'An error occurred'})

    return render(request, 'mill_line.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Mill Line Configuration', 'url': ''},
        ],
        'active_menu': 'millLine',
        'lines': lines,
        'mill': mill,
    })

def format_layout_data(layout_data):
    formatted_connections = []
    device_ids = []
    drawflow = layout_data.get('drawflow', {}).get('Home', {}).get('data', {})
    
    machine_type_mapping = {
        'carding': 'C1',
        'breaker': 'B1',
        'unilap': 'U1',
        'comber': 'K1',
        'finisher': 'F1',
        'roving': 'R1'
    }

    for node_id, node in drawflow.items():
        node_name = node.get('name')
        node_type = node_name.split()[0].lower()  
        node_number = node_name.split()[1]
        machine_prefix = machine_type_mapping.get(node_type, 'Unknown')

        for output_name, output in node.get('outputs', {}).items():
            if 'connections' in output and output['connections']:
                for connection in output['connections']:
                    target_node = connection['node']
                    target_output = connection['output']
                    target_node_data = drawflow.get(target_node, {})
                    target_node_name = target_node_data.get('name', '')
                    target_node_type = target_node_name.split()[0].lower() 
                    target_node_number = target_node_name.split()[1]
                    target_machine_prefix = machine_type_mapping.get(target_node_type, 'Unknown')
                    
                    formatted_connection = f"PO{machine_prefix}{node_number}{output_name.split('_')[1].zfill(3)} -> PI{target_machine_prefix}{target_node_number}{target_output.split('_')[1].zfill(3)}"
                    formatted_connections.append(formatted_connection)

        if 'inputs' in node and node['inputs']:
            device_id = f"PI{machine_prefix}{node_number}" 
            device_ids.append(device_id)
        if 'outputs' in node and node['outputs']:
            device_id = f"PO{machine_prefix}{node_number}"  
            device_ids.append(device_id)

    return formatted_connections, device_ids

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['red_flag_view'])
def redFlagging(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    millLine = MillLine.objects.filter(mill=mill)
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            machine_ids = data.get('machine_ids', [])
            start_time = data.get('start_time')
            end_time = data.get('end_time')
            if not machine_ids or not start_time or not end_time:
                return JsonResponse({'error': 'Missing required fields'}, status=400)
            invalid_ids = [machine_id for machine_id in machine_ids if not machine_id.isdigit()]
            if invalid_ids:
                return JsonResponse({'error': f'Invalid machine IDs: {", ".join(invalid_ids)}'}, status=400)
            start_time = timezone.make_aware(timezone.datetime.fromisoformat(start_time))
            end_time = timezone.make_aware(timezone.datetime.fromisoformat(end_time))
            machines = MillMachine.objects.filter(id__in=machine_ids)
            if not machines.exists():
                return JsonResponse({'error': 'No valid machines found for the provided IDs'}, status=400)
            for machine in machines:
                machine.is_red_flag = True
                machine.red_flag_from = start_time
                machine.red_flag_to = end_time
                machine.save()

            return JsonResponse({'success': True})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
        except KeyError as e:
            return JsonResponse({'error': f'Missing field: {str(e)}'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    red_flagged_machines = MillMachine.objects.filter(is_red_flag=True, mill=mill).values_list('id', flat=True)

    return render(request, 'process_redFlagging.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Process Management', 'url': ''},
        ],
        'active_menu': 'millProcesses',
        'millLine': millLine,
        'mill': mill,
        'red_flagged_machines': list(red_flagged_machines),
    })

def list_machines(request, line_id):
    machines = MillMachine.objects.filter(line_id=line_id).values('id', 'machine_name', 'model')
    machine_list = list(machines)
    return JsonResponse({'machines': machine_list})

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['can_manage_view'])
def canManage(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    lines = MillLine.objects.filter(mill=mill)
    selected_line_id = request.GET.get('line_id')
    if selected_line_id:
        selected_line = MillLine.objects.get(id=selected_line_id)
    else:
        selected_line = lines.first()
        if selected_line:
            selected_line_id = selected_line.id  
    
    if selected_line_id:
        machines = MachineConnectionLog.objects.filter(line_id=selected_line_id)
    else:
        machines = MachineConnectionLog.objects.all()
    lines = MillLine.objects.filter(mill=mill) 
    selected_line = MillLine.objects.filter(id=selected_line_id).first() if selected_line_id else None
    
    return render(request, 'process_canManage.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Process Management', 'url': ''},
        ],
        'active_menu': 'millProcesses',
        'machines': machines,
        'mill': mill,
        'lines': lines,
        'selected_line': selected_line,  
    })

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['non_scan_view'])
def nonScan(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    machines = MillMachine.objects.filter(mill=mill)

    machine_settings = {}
    for machine in machines:
        setting, created = MachineSetting.objects.get_or_create(machine=machine)
        machine_settings[machine.id] = {
            'input_time': setting.input_time.strftime('%H:%M') if setting.input_time else '00:00',
            'input_tolerance': setting.input_tolerance.strftime('%H:%M') if setting.input_tolerance else '00:00',
            'output_time': setting.output_time.strftime('%H:%M') if setting.output_time else '00:00',
            'output_tolerance': setting.output_tolerance.strftime('%H:%M') if setting.output_tolerance else '00:00',
        }

    return render(request, 'process_nonScan.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Process Management', 'url': ''},
        ],
        'active_menu': 'millProcesses',
        'machines': machines,
        'machine_settings': machine_settings,
        'mill': mill
    })

@csrf_exempt  
def save_machine_settings(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            settings_data = data.get('settings', [])

            for setting in settings_data:
                machine_id, input_time, input_tolerance, output_time, output_tolerance = setting.split(',')
                machine = MillMachine.objects.get(id=machine_id)
                MachineSetting.objects.update_or_create(
                    machine=machine,
                    defaults={
                        'input_time': timezone.datetime.strptime(input_time, '%H:%M').time(),
                        'input_tolerance': timezone.datetime.strptime(input_tolerance, '%H:%M').time(),
                        'output_time': timezone.datetime.strptime(output_time, '%H:%M').time(),
                        'output_tolerance': timezone.datetime.strptime(output_tolerance, '%H:%M').time(),
                    }
                )
            return JsonResponse({'status': 'success'})

        except Machine.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Machine not found.'}, status=404)
        except ValueError as ve:
            return JsonResponse({'status': 'error', 'message': str(ve)}, status=400)
        except Exception as e:
            print(f"Error saving settings: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)

def notAuth(request):
    return render(request, 'unauth.html')

def lineAdd(request):
    return render(request, 'line_add.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Mill Line Configuration', 'url': '/mill-line'},
            {'name': 'Mill Add Line', 'url': '/line-add'},
        ],
        'active_menu': 'millLine'
    })

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['reports_view'])
def millReportAgeing(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    mill_id = mill.id
    millImg = MillInfo.objects.filter(mill_id=mill_id).first()
    selected_line_id = request.GET.get('line_id')
    lines = MillLine.objects.filter(mill=mill)
    if selected_line_id:
        selected_line = MillLine.objects.get(id=selected_line_id)
        ageing = MachineConnectionLog.objects.filter(mill_id=mill_id, line_id=selected_line_id, input_machine=None)
    else:
        selected_line = None
        ageing = MachineConnectionLog.objects.filter(mill_id=mill_id, input_machine=None)
    current_time = timezone.now()
    for data in ageing:
        time_difference = current_time - data.output_time
        ageing_hrs = time_difference.total_seconds() / 3600
        data.ageing_hrs = round(ageing_hrs)
    return render(request, 'mill_report_ageing.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Mill Report', 'url': ''},
        ],
        'active_menu': 'millReport',
        'mill': mill,
        'millImg': millImg,
        'lines': lines,  
        'selected_line': selected_line,  
        'ageing': ageing,  
        'current_time': current_time,  
    })

@login_required
@role_required(['Admin', 'Maintenance', 'Supervisor'])
@permission_required(['reports_view'])
def millReportMachineStop(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    mill_id = mill.id
    millImg = MillInfo.objects.filter(mill_id=mill_id).first()
    stoppage = MachineConnectionLog.objects.filter(mill_id=mill_id, input_machine=None)
    return render(request, 'mill_report_machinestop.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Mill Report', 'url': ''},
        ],
        'active_menu': 'millReport',
        'mill': mill,
        'millImg': millImg,
        'stoppage':stoppage
    })


def base(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    mill_info = request.user.mill.info if request.user.is_authenticated else None
    return render(request, 'topbar.html',{
        'mill_info': mill_info,
    })

def get_machines(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    machines = list(MillMachine.objects.filter(mill=mill).values('id', 'machine_name', 'image', 'num_inputs', 'num_outputs'))
    return JsonResponse(machines, safe=False)