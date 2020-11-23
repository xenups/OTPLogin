import requests


def get_token():
    url = "http://RestfulSms.com/api/Token"
    payload = {"UserApiKey": "api_key", "SecretKey": "key!@#"}
    headers = {
        'Content-Type': "application/json",
    }
    response = requests.request("POST", url, json=payload, headers=headers)
    response = response.json()
    return response["TokenKey"]


def send_message(phone, message):
    token = str(get_token())
    messages = str(message)
    url = "http://RestfulSms.com/api/MessageSend"
    payload = {"Messages": [messages], "MobileNumbers": [phone], "LineNumber": "30004554552893"}
    headers = {
        'Content-Type': "application/json",
        'x-sms-ir-secure-token': token,
    }

    response = requests.request("POST", url, json=payload, headers=headers)
