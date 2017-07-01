import json
import uuid

import flask

from flask.globals import request
from werkzeug.security import check_password_hash, generate_password_hash

from couchdropservice import application, config__get
from couchdropservice.model import Account, PushToken, TempCredentials, Storage


def __internal_check_password_matches(account, supplied_password):
    if "sha" in account.password:
        return check_password_hash(account.password, supplied_password)
    return account.password == supplied_password


@application.route("/authenticate", methods=["POST"])
def push_authenticate():
    username = request.form.get("username")
    password = request.form.get("password")

    account = flask.g.db_session.query(Account).filter(Account.username == username).scalar()
    if account:
        if not __internal_check_password_matches(account, password):
            return flask.jsonify(err="Account was invalid"), 403

        new_token = PushToken()
        new_token.account = account.username
        new_token.authenticated_user = username
        new_token.token = str(uuid.uuid4())
        new_token.admin = True
        flask.g.db_session.add(new_token)
        return flask.jsonify(token=new_token.token)

    temp_account = flask.g.db_session.query(TempCredentials).filter(TempCredentials.username == username).scalar()
    if temp_account:
        if temp_account.password != password:
            return flask.jsonify(err="Account was invalid"), 403

        new_token = PushToken()
        new_token.account = temp_account.account
        new_token.token = str(uuid.uuid4())
        new_token.authenticated_user = username
        new_token.admin = False
        flask.g.db_session.add(new_token)
        return flask.jsonify(token=new_token.token)

    return flask.jsonify(err="Account was invalid"), 403


@application.route("/authenticate/get/token", methods=["POST"])
def push_authenticate_get_token():
    username = request.form.get("username")
    service_token = request.form.get("service_token")

    if service_token != config__get("COUCHDROP_SERVICE__SERVICE_TOKEN"):
        return flask.jsonify(err="This route requires a service token"), 403

    account = flask.g.db_session.query(Account).filter(Account.username == username).scalar()
    if account:
        new_token = PushToken()
        new_token.account = account.username
        new_token.authenticated_user = username
        new_token.token = str(uuid.uuid4())
        new_token.admin = True
        flask.g.db_session.add(new_token)
        return flask.jsonify(token=new_token.token)
    return flask.jsonify(err="Account was invalid"), 403


@application.route("/authenticate/get/pub", methods=["POST"])
def push_authenticate_get_pub():
    username = request.form.get("username")
    service_token = request.form.get("service_token")

    if service_token != config__get("COUCHDROP_SERVICE__SERVICE_TOKEN"):
        return flask.jsonify(err="This route requires a service token"), 403

    account = flask.g.db_session.query(Account).filter(Account.username == username).scalar()
    if account:
        if account.endpoint__valid_public_key:
            return flask.jsonify(public_key=account.endpoint__valid_public_key)
        return flask.jsonify(err="No public key"), 403
    return flask.jsonify(err="Account was invalid"), 403


@application.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    email_address = request.form.get("email_address")
    password = request.form.get("password")

    account = flask.g.db_session.query(Account).filter(Account.email_address == email_address).scalar()
    if account:
        return flask.jsonify(err="Username already exists"), 403

    new_account = Account()
    new_account.username = username
    new_account.email_address = email_address
    new_account.password = generate_password_hash(password)
    flask.g.db_session.add(new_account)
    return flask.jsonify({}), 200


@application.route("/manage/account", methods=["GET"])
def manage_authenticate():
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    account = flask.g.db_session.query(Account).filter(Account.username == token_object.account).scalar()
    ret = {
        "username": account.username,
        "email_address": account.email_address,
        "endpoint__amazon_s3_enabled": account.endpoint__amazon_s3_enabled,
        "endpoint__amazon_s3_access_key_id": account.endpoint__amazon_s3_access_key_id,
        "endpoint__amazon_s3_access_secret_key": account.endpoint__amazon_s3_access_secret_key,
        "endpoint__amazon_s3_bucket": account.endpoint__amazon_s3_bucket,

        "endpoint__dropbox_enabled": account.endpoint__dropbox_enabled,
        "endpoint__dropbox_access_token": account.endpoint__dropbox_access_token,
        "endpoint__dropbox_user_id": account.endpoint__dropbox_user_id,

        "endpoint__valid_public_key": account.endpoint__valid_public_key
    }

    return flask.jsonify(account=ret)


@application.route("/manage/account", methods=["POST"])
def manage_authenticate_post():
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    account = flask.g.db_session.query(Account).filter(Account.username == token_object.account).scalar()

    data = json.loads(request.data)
    if data.get("password"):
        account.password = generate_password_hash(data.get("password"))
    if data.get("email_address"):
        account.email_address = data.get("email_address")

    if data.get("endpoint__amazon_s3_access_key_id"):
        account.endpoint__amazon_s3_access_key_id = data.get("endpoint__amazon_s3_access_key_id")
    if data.get("endpoint__amazon_s3_access_secret_key"):
        account.endpoint__amazon_s3_access_secret_key = data.get("endpoint__amazon_s3_access_secret_key")
    if data.get("endpoint__amazon_s3_bucket"):
        account.endpoint__amazon_s3_bucket = data.get("endpoint__amazon_s3_bucket")
    if "endpoint__amazon_s3_enabled" in data:
        account.endpoint__amazon_s3_enabled = data.get("endpoint__amazon_s3_enabled")
    if "endpoint__dropbox_enabled" in data:
        account.endpoint__dropbox_enabled = data.get("endpoint__dropbox_enabled")
    if data.get("endpoint__dropbox_access_token"):
        account.endpoint__dropbox_access_token = data.get("endpoint__dropbox_access_token")
    if data.get("endpoint__dropbox_user_id"):
        account.endpoint__dropbox_user_id = data.get("endpoint__dropbox_user_id")
    if data.get("endpoint__valid_public_key"):
        account.endpoint__valid_public_key = data.get("endpoint__valid_public_key")
    return flask.jsonify({})


@application.route("/manage/account/storage", methods=["GET"])
def manage_storage_get():
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    ret = []
    storage_items = flask.g.db_session.query(Storage).filter(Storage.account == token_object.account).all()
    for storage_item in storage_items:
        elem = {
            "id": storage_item.id,
            "account": storage_item.account,
            "store_type": storage_item.store_type,
            "path": storage_item.path,
            "permissions": storage_item.permissions,
            "endpoint__dropbox_access_token": storage_item.endpoint__dropbox_access_token,
            "endpoint__dropbox_user_id": storage_item.endpoint__dropbox_user_id,
            "endpoint__amazon_s3_access_key_id": storage_item.endpoint__amazon_s3_access_key_id,
            "endpoint__amazon_s3_access_secret_key": storage_item.endpoint__amazon_s3_access_secret_key,
            "endpoint__amazon_s3_bucket": storage_item.endpoint__amazon_s3_bucket,

            "endpoint__webdav_username": storage_item.endpoint__webdav_username,
            "endpoint__webdav_password": storage_item.endpoint__webdav_password,
            "endpoint__webdav_hostname": storage_item.endpoint__webdav_hostname,
            "endpoint__webdav_path": storage_item.endpoint__webdav_path,
            "endpoint__webdav_protocol": storage_item.endpoint__webdav_protocol,
        }

        ret.append(elem)

    return flask.jsonify(storage=ret)


@application.route("/manage/account/storage", methods=["POST"])
def manage_storage_set():
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    data = json.loads(request.data)
    storage_entry = flask.g.db_session.query(Storage).filter(
        Storage.account == token_object.account, Storage.id == data.get("id")
    ).scalar()

    if data.get("endpoint__amazon_s3_access_key_id"):
        storage_entry.endpoint__amazon_s3_access_key_id = data.get("endpoint__amazon_s3_access_key_id")
    if data.get("endpoint__amazon_s3_access_secret_key"):
        storage_entry.endpoint__amazon_s3_access_secret_key = data.get("endpoint__amazon_s3_access_secret_key")
    if data.get("endpoint__amazon_s3_bucket"):
        storage_entry.endpoint__amazon_s3_bucket = data.get("endpoint__amazon_s3_bucket")

    if data.get("endpoint__dropbox_access_token"):
        storage_entry.endpoint__dropbox_access_token = data.get("endpoint__dropbox_access_token")
    if data.get("endpoint__dropbox_user_id"):
        storage_entry.endpoint__dropbox_user_id = data.get("endpoint__dropbox_user_id")

    if data.get("endpoint__webdav_username"):
        storage_entry.endpoint__webdav_username = data.get("endpoint__webdav_username")
    if data.get("endpoint__webdav_password"):
        storage_entry.endpoint__webdav_password = data.get("endpoint__webdav_password")
    if data.get("endpoint__webdav_hostname"):
        storage_entry.endpoint__webdav_hostname = data.get("endpoint__webdav_hostname")
    if data.get("endpoint__webdav_path"):
        storage_entry.endpoint__webdav_path = data.get("endpoint__webdav_path")
    if data.get("endpoint__webdav_protocol"):
        storage_entry.endpoint__webdav_protocol = data.get("endpoint__webdav_protocol")

    storage_entry.store_type = data.get("store_type")
    storage_entry.path = data.get("path")
    storage_entry.permissions = data.get("permissions")

    return flask.jsonify({})


@application.route("/manage/account/storage", methods=["PUT"])
def manage_storage_put():
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    entry = Storage()
    entry.id = str(uuid.uuid4())
    entry.path = "/"
    entry.permissions = "rw"
    entry.account = token_object.account
    flask.g.db_session.add(entry)
    return flask.jsonify({})


@application.route("/manage/account/storage", methods=["DELETE"])
def manage_storage_delete():
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    data = json.loads(request.data)
    storage_entry = flask.g.db_session.query(Storage).filter(
        Storage.account == token_object.account, Storage.id == data.get("id")
    ).scalar()

    flask.g.db_session.delete(storage_entry)
    return flask.jsonify({})
