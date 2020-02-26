import datetime
import json
import secrets

from django.core.cache import cache
from django.utils.timezone import utc


def get_time_diff(last_update_time):
    if last_update_time:
        now = datetime.datetime.now().replace(tzinfo=utc)
        timediff = now - last_update_time
        return timediff.total_seconds()


def generate_otp_code():
    return secrets.SystemRandom().randrange(999, 9999)


def get_cache_value(key, custom_value_name):
    json_value_data = cache.get(key)
    print(json_value_data)
    if json_value_data is not None:
        __value = (json.loads(json_value_data)).get(custom_value_name, None)
        return __value
    return None


def set_cache_multiple_value(key, value, custom_value_name, ttl=60):
    print('set called')
    json_value = cache.get(key)

    try:
        exist_json = json.loads(json_value)
        dict_value = {custom_value_name: value}
        dict_value.update(exist_json)
        json_data = json.dumps(dict_value)
        __set_status = cache.set(key, json_data, timeout=ttl)
        print('data has been set')
        return __set_status
    except:
        print('its not json')
        json_data = json.dumps({custom_value_name: str(value)})
        __set_status = cache.set(key, json_data, timeout=ttl)
        return __set_status
