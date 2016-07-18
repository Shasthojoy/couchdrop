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
        config__get("COUCHDROP_API_URL") + "/authenticate",
        data=dict(username=username, password=password)
    )

    if ret.status_code == 200:
        return json.loads(ret.text)["token"]
    return None


def register(username, password, email_address):
    ret = requests.post(
        config__get("COUCHDROP_API_URL") + "/register",
        data=dict(username=username, password=password, email_address=email_address)
    )

    if ret.status_code == 200:
        return json.loads(ret.text)
    return None


def api__get_account(token):
    ret = requests.get(
        config__get("COUCHDROP_API_URL") + "/manage/account?token=" + token,
    )

    ret_dict = None
    if ret.status_code == 200:
        ret_dict = json.loads(ret.text)
    return ret_dict["account"]


def api__get_audit(token):
    ret = requests.get(
        config__get("COUCHDROP_API_URL") + "/manage/files?token=" + token,
    )

    ret_dict = None
    if ret.status_code == 200:
        ret_dict = json.loads(ret.text)
    return ret_dict["files"]


def api__get_credentials(token):
    ret = requests.get(
        config__get("COUCHDROP_API_URL") + "/manage/credentials?token=" + token,
    )

    ret_dict = None
    if ret.status_code == 200:
        ret_dict = json.loads(ret.text)
    return ret_dict["credentials"]


def api__get_credentials_create(token):
    requests.put(
        config__get("COUCHDROP_API_URL") + "/manage/credentials?token=" + token,
    )

def api__get_credentials_delete(token, username):
    requests.delete(
        config__get("COUCHDROP_API_URL") + "/manage/credentials/%s/delete?token=%s" % (username, token),
    )


def api__get_filelink(file_id, token):
    ret = requests.get(
        config__get("COUCHDROP_API_URL") + "/manage/files/%s/download?token=%s" % (file_id, token),
    )

    ret_dict = None
    if ret.status_code == 200:
        ret_dict = json.loads(ret.text)
    return ret_dict["url"]


def api__set_account(token, account):
    requests.post(
        config__get("COUCHDROP_API_URL") + "/manage/account?token=" + token,
        data=json.dumps(account)
    )
