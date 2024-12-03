# from django.http import HttpResponseForbidden
# from functools import wraps
# """ from .models import UserProfile
# import json """

# def role_required(allowed_roles):
#     """
#     Decorator to check if the user has one of the allowed roles.
#     """
#     def decorator(view_func):
#         @wraps(view_func)
#         def _wrapped_view(request, *args, **kwargs):
#             user_profile = getattr(request.user, 'userprofile', None)
#             if user_profile and user_profile.role in allowed_roles:
#                 return view_func(request, *args, **kwargs)
#             else:
#                 return HttpResponseForbidden("You do not have permission to access this page.")
#         return _wrapped_view
#     return decorator

# def permission_required(required_permissions):
#     """
#     Decorator to check if the user has the required permissions.
#     """
#     def decorator(view_func):
#         @wraps(view_func)
#         def _wrapped_view(request, *args, **kwargs):
#             user_profile = getattr(request.user, 'userprofile', None)
#             if user_profile:
#                 try:
#                     # Load permissions from the UserProfile model
#                     permissions = user_profile.permissions
#                     print(f"User Permissions: {permissions}")  # Debug line
#                     print(f"Required Permissions: {required_permissions}")  # Debug line
#                     if all(permissions.get(perm, False) for perm in required_permissions):
#                         return view_func(request, *args, **kwargs)
#                 except (ValueError, TypeError) as e:
#                     print(f"Error: {e}")  # Debug line
#                     pass  # Handle JSON decoding errors or invalid data
#             return HttpResponseForbidden("You do not have permission to access this page.")
#         return _wrapped_view
#     return decorator

from django.shortcuts import redirect
from django.conf import settings
from functools import wraps

def role_required(allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect(settings.NOTAUTH_URL)
            
            user_profile = getattr(request.user, 'userprofile', None)
            if user_profile and user_profile.role in allowed_roles:
                return view_func(request, *args, **kwargs)
            else:
                return redirect(settings.NOTAUTH_URL)  
        return _wrapped_view
    return decorator

def permission_required(required_permissions):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect(settings.NOTAUTH_URL)
            
            user_profile = getattr(request.user, 'userprofile', None)
            if user_profile:
                if user_profile.role == 'Admin':
                    return view_func(request, *args, **kwargs)
                
                try:
                    permissions = user_profile.permissions
                    if all(permissions.get(perm, False) for perm in required_permissions):
                        return view_func(request, *args, **kwargs)
                except (ValueError, TypeError) as e:
                    print(f"Error: {e}")
                    pass
            
            return redirect(settings.NOTAUTH_URL)
        return _wrapped_view
    return decorator
