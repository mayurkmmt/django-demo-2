import json
import uuid

from django.conf import settings
from pyfcm import FCMNotification
from redis import StrictRedis

# from demo2_common.models import FCMDevice


# Function to add new notifications for user
def add_notification(user_id, data):
    r = StrictRedis(
        host=settings.NOTIFY_REDIS_HOST,
        db=settings.NOTIFY_REDIS_DB,
        password=settings.NOTIFY_REDIS_PASSWORD,
        port=6379,
    )
    notification_id = str(uuid.uuid4())
    r.hset("%s_notifications" % user_id, notification_id, json.dumps(data))
    r.expire("%s_notifications" % user_id, 86400)


# Function to set the notification as read, your Frontend looks at the "read" key in
# Notification's data to determine how to show the notification
def set_notification_as_read(user_id, notification_id):
    r = StrictRedis(
        host=settings.NOTIFY_REDIS_HOST,
        db=settings.NOTIFY_REDIS_DB,
        password=settings.NOTIFY_REDIS_PASSWORD,
        port=6379,
    )
    data = json.loads(r.hget("%s_notifications" % user_id, notification_id))
    data["read"] = True
    add_notification(user_id, notification_id, data)


# Gets all notifications for a user, you can sort them based on a key like "date" in Frontend
def get_notifications(user_id):
    r = StrictRedis(
        host=settings.NOTIFY_REDIS_HOST,
        db=settings.NOTIFY_REDIS_DB,
        password=settings.NOTIFY_REDIS_PASSWORD,
        port=6379,
    )
    return r.hgetall("%s_notifications" % user_id)


def send_user_fcm_notification(user_id, notification_type):
    title = None
    message = None

    # device = FCMDevice.objects.filter(user_id=user_id).last()

    if notification_type == "enable_https":
        title = "Enable HTTPS"
        message = "Batch enable https operation is successfully completed."
    elif notification_type == "enable_force_https":
        title = "Enable Force HTTPS"
        message = "Batch enable force https operation is successfully completed."
    elif notification_type == "disable_force_https":
        title = "Disable Force HTTPS"
        message = "Batch disable force https operation is successfully completed."
    elif notification_type == "clear_cache":
        title = "Clear Cache"
        message = "Batch clear cache operation is successfully completed."
    elif notification_type == "batch_delete":
        title = "Batch Delete"
        message = "Batch delete operation is successfully completed."
    elif notification_type == "batch_active":
        title = "Batch Active"
        message = "Batch active operation is successfully completed."
    elif notification_type == "batch_deactivate":
        title = "Batch Deactivate"
        message = "Batch deactivate operation is successfully completed."
    elif notification_type == "import":
        title = "Import"
        message = "Import domains operation is successfully completed."

    # if device and notification_type and message:
    #     push_service = FCMNotification(api_key=settings.FCM_DJANGO_SETTINGS['FCM_SERVER_KEY'])
    #     push_service.notify_single_device(registration_id=device.registration_id, message_title=title,
    #                                       message_body=message)
    #     add_notification(user_id, {
    #         'title': title,
    #         'message': message,
    #         'read': False
    #     })

    return True
