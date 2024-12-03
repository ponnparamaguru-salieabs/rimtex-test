from .models import Log

def create_log(action, model_name, model_id, user, details=''):
    log_entry = Log(
        action=action,
        model_name=model_name,
        model_id=model_id,
        user=user,
        details=details
    )
    log_entry.save()