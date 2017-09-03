import json
import uuid

import flask

from flask.globals import request
from werkzeug.security import check_password_hash, generate_password_hash

from couchdropservice import application, config__get
from couchdropservice.middleware import stripe_api
from couchdropservice.middleware.email_sender import mandrill__email_confirm__email, mandrill__email_password_reset
from couchdropservice.middleware.stripe_api import stripe__subscribe_customer, stripe__get_customer, \
    stripe__cancel_existing_subscriptions
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

        if not account.email_confirmation_code_accepted:
            return flask.jsonify(err="Account email address has not been registered"), 403

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
        if not account.email_confirmation_code_accepted:
            return flask.jsonify(err="Account email address has not been registered"), 403

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

    #Sanitise username
    account = flask.g.db_session.query(Account).filter(Account.email_address == email_address).scalar()
    if account:
        return flask.jsonify(err="Email already exists"), 403

    account = flask.g.db_session.query(Account).filter(Account.username == username).scalar()
    if account:
        return flask.jsonify(err="Username already exists"), 403

    new_account = Account()
    new_account.username = username
    new_account.email_address = email_address
    new_account.subscription_type = "freeby"
    new_account.password = generate_password_hash(password)
    new_account.email_confirmation_code = str(uuid.uuid4())
    new_account.email_confirmation_code_accepted = False

    stripe_customer = stripe_api.stripe__create_customer(email_address)
    if stripe_customer:
        new_account.stripe_customer_id = stripe_customer["id"]
        if request.form.get("subscription_type") != "freeby":
            stripe__subscribe_customer(new_account.stripe_customer_id, request.form.get("stripe_token"), request.form.get("subscription_type"))
        new_account.subscription_type = request.form.get("subscription_type")

    flask.g.db_session.add(new_account)
    mandrill__email_confirm__email(
        new_account.email_address, new_account.email_address, new_account.email_confirmation_code
    )

    return flask.jsonify({}), 200


@application.route("/resetpassword/<email_address>", methods=["POST"])
def resetpassword(email_address):
    account = flask.g.db_session.query(Account).filter(Account.email_address == email_address).scalar()
    if not account:
        return flask.jsonify(err="Email already exists"), 403

    account.reset_password_code = str(uuid.uuid4())
    mandrill__email_password_reset(
        account.email_address, account.email_address, account.reset_password_code
    )
    return flask.jsonify({}), 200


@application.route("/resetpassword/reset/<code>", methods=["POST"])
def resetpassword_confirm(code):
    if not code:
        return flask.jsonify(err="Code is empty"), 403

    account = flask.g.db_session.query(Account).filter(Account.reset_password_code == code).scalar()
    if not account:
        return flask.jsonify(err="Code is not valid"), 403

    password = request.form.get("password")
    if not password:
        flask.jsonify(err="Password was invalid"), 403

    account.password = password
    account.reset_password_code = ""
    return flask.jsonify({}), 200


@application.route("/register/confirm/<code>", methods=["POST"])
def register_confirm(code):
    if not code:
        return flask.jsonify(err="Code is empty"), 403

    account = flask.g.db_session.query(Account).filter(Account.email_confirmation_code == code).scalar()
    if not account:
        return flask.jsonify(err="Code does not exist"), 403

    account.email_confirmation_code_accepted = True
    account.email_confirmation_code = ""
    return flask.jsonify({"email_address": account.email_address}), 200


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
        "subscription_type": account.subscription_type,
        "endpoint__valid_public_key": account.endpoint__valid_public_key,
    }

    try:
        ret["stripe__customer"] = stripe__get_customer(account.stripe_customer_id)
    except:
        pass

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
    if data.get("endpoint__valid_public_key"):
        account.endpoint__valid_public_key = data.get("endpoint__valid_public_key")
    return flask.jsonify({})


@application.route("/manage/account/subscription", methods=["POST"])
def manage_account_subscription_post():
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    account = flask.g.db_session.query(Account).filter(Account.username == token_object.account).scalar()
    data = json.loads(request.data)
    if account.subscription_type == data.get("subscription_type"):
        # subscription is already the same
        pass
    else:
        # subscription needs changing so lets change it
        if data.get("subscription_type") == "freeby":
            stripe__cancel_existing_subscriptions(account.stripe_customer_id)
        elif data.get("subscription_type") == "couchdrop_standard":
            stripe__subscribe_customer(
                account.stripe_customer_id, data.get("stripe_token"), data.get("subscription_type")
            )
        elif data.get("subscription_type") == "couchdrop_premium":
            stripe__subscribe_customer(
                account.stripe_customer_id, data.get("stripe_token"), data.get("subscription_type")
            )

        account.subscription_type = data.get("subscription_type")
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
            "endpoint__googledrive_credentials": storage_item.endpoint__googledrive_credentials,
            "endpoint__googledrive_credentials_active": not not storage_item.endpoint__googledrive_credentials,
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

    if data.get("endpoint__googledrive_credentials"):
        storage_entry.endpoint__googledrive_credentials = data.get("endpoint__googledrive_credentials")

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
