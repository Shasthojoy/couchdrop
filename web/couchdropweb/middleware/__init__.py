import json

import requests

from couchdropweb import config__get


class User:
    token = None

    def __init__(self, token):
        self.token = token

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.token


def authenticate(username, password):
    ret = requests.post(
        config__get("COUCHDROP_WEB__API_URL") + "/authenticate",
        data=dict(username=username, password=password)
    )

    if ret.status_code == 200:
        return json.loads(ret.text)["token"]
    return None


def register(username, password, email_address, subscription_type, stripe_token):
    ret = requests.post(
        config__get("COUCHDROP_WEB__API_URL") + "/register",
        data=dict(
            username=username,
            password=password,
            email_address=email_address,
            subscription_type=subscription_type,
            stripe_token=stripe_token
        )
    )

    return ret.status_code == 200

def register_confirm(confirm_code):
    ret = requests.post(
        config__get("COUCHDROP_WEB__API_URL") + "/register/confirm/" + confirm_code,
    )

    if ret.status_code == 200:
        return json.loads(ret.text)
    return None

def request_reset_password(email_address):
    ret = requests.post(
        config__get("COUCHDROP_WEB__API_URL") + "/resetpassword/" + email_address,
    )

    if ret.status_code == 200:
        return json.loads(ret.text)
    return None

def reset_password(code, password):
    ret = requests.post(
        config__get("COUCHDROP_WEB__API_URL") + "/resetpassword/reset/" + code,data=dict(password=password)
    )

    if ret.status_code == 200:
        return json.loads(ret.text)
    return None


def resetpassword_confirm(code, password):
    ret = requests.post(
        config__get("COUCHDROP_WEB__API_URL") + "/resetpassword/reset/" + code,
        data=dict(password=password)
    )

    if ret.status_code == 200:
        return json.loads(ret.text)
    return None


def api__get_account(token):
    ret = requests.get(
        config__get("COUCHDROP_WEB__API_URL") + "/manage/account?token=" + token,
    )

    ret_dict = None
    if ret.status_code == 200:
        ret_dict = json.loads(ret.text)
    return ret_dict["account"]


def api__get_storage(token):
    ret = requests.get(
        config__get("COUCHDROP_WEB__API_URL") + "/manage/account/storage?token=" + token,
    )

    ret_dict = None
    if ret.status_code == 200:
        ret_dict = json.loads(ret.text)
    return ret_dict["storage"]

def api__put_storage(token):
    requests.put(
        config__get("COUCHDROP_WEB__API_URL") + "/manage/account/storage?token=" + token,
    )

def api__post_storage(token, bucket):
    requests.post(
        config__get("COUCHDROP_WEB__API_URL") + "/manage/account/storage?token=" + token,
        data=json.dumps(bucket)
    )

def api__update_subscription(token, subscription_type, stripe_token):
    requests.post(
        config__get("COUCHDROP_WEB__API_URL") + "/manage/account/subscription?token=" + token,
        data=json.dumps({
            "subscription_type" : subscription_type,
            "stripe_token" : stripe_token,
        })
    )

def api__delete_storage(token, id):
    requests.delete(
        config__get("COUCHDROP_WEB__API_URL") + "/manage/account/storage?token=" + token,
        data=json.dumps({"id": id})
    )


def api__get_audit(token):
    ret = requests.get(
        config__get("COUCHDROP_WEB__API_URL") + "/manage/files?token=" + token,
    )

    ret_dict = None
    if ret.status_code == 200:
        ret_dict = json.loads(ret.text)
    return ret_dict["files"]


def api__get_credentials(token):
    ret = requests.get(
        config__get("COUCHDROP_WEB__API_URL") + "/manage/credentials?token=" + token,
    )

    ret_dict = None
    if ret.status_code == 200:
        ret_dict = json.loads(ret.text)
    return ret_dict["credentials"]


def api__get_credentials_create(token):
    requests.put(
        config__get("COUCHDROP_WEB__API_URL") + "/manage/credentials?token=" + token,
    )

def api__get_credentials_save(token, object):
    requests.post(
        config__get("COUCHDROP_WEB__API_URL") + "/manage/credentials?token=" + token, data=json.dumps(object)
    )

def api__get_credentials_delete(token, username):
    requests.delete(
        config__get("COUCHDROP_API_URL") + "/manage/credentials/%s/delete?token=%s" % (username, token),
    )


def api__get_filelink(file_id, token):
    ret = requests.get(
        config__get("COUCHDROP_WEB__API_URL") + "/manage/files/%s/download?token=%s" % (file_id, token),
    )

    ret_dict = None
    if ret.status_code == 200:
        ret_dict = json.loads(ret.text)
    return ret_dict["url"]


def api__set_account(token, account):
    requests.post(
        config__get("COUCHDROP_WEB__API_URL") + "/manage/account?token=" + token,
        data=json.dumps(account)
    )
