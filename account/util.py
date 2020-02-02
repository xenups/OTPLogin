import datetime
import secrets
from django.utils.timezone import utc


def get_time_diff(last_update_time):
    if last_update_time:
        now = datetime.datetime.now().replace(tzinfo=utc)
        timediff = now - last_update_time
        return timediff.total_seconds()


def generate_otp_code():
    return secrets.SystemRandom().randrange(999, 9999)
