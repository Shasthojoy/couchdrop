import base64
import uuid

import boto3
import datetime
import flask
from botocore.exceptions import ClientError
from dropbox import dropbox
from dropbox.exceptions import ApiError

from flask.globals import request

from couchdropservice import application, config__get
from couchdropservice.middleware import easywebdav
from couchdropservice.middleware.easywebdav import OperationFailed
from couchdropservice.middleware.email_sender import mandrill__send_file__email
from couchdropservice.model import Account, PushToken, File, Storage, TempCredentials


@application.route("/manage/files", methods=["GET"])
def manage_audit():
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    files = flask.g.db_session.query(File).filter(
        File.account == token_object.account
    ).order_by(File.time.desc()).all()
    ret = []
    for file in files:
        ret.append({
            "id": file.id,
            "time": file.time,
            "filename": file.filename,
            "token": file.token,
            "storage_engine": file.storage_engine,
            "uploader": file.authenticated_user
        })
    return flask.jsonify(files=ret)


def __generate_dropbox_url(account, file):
    dbx = dropbox.Dropbox(account.endpoint__dropbox_access_token)
    return dbx.files_get_temporary_link(file.filename).link


def __generate_s3_url(account, file):
    client = boto3.client(
        's3',
        aws_access_key_id=account.endpoint__amazon_s3_access_key_id,
        aws_secret_access_key=account.endpoint__amazon_s3_access_secret_key
    )

    path = file.filename.lstrip('/')
    url = client.generate_presigned_url(
        'get_object',
        Params={'Bucket': account.endpoint__amazon_s3_bucket, 'Key': path},
        ExpiresIn=100
    )
    return url


def __upload_dropbox(store, file_object, full_path):
    dbx = dropbox.Dropbox(store.endpoint__dropbox_access_token)
    dbx.files_upload(file_object, full_path)


def __download_dropbox(store, full_path):
    try:
        dbx = dropbox.Dropbox(store.endpoint__dropbox_access_token)
        md, res = dbx.files_download(full_path)
        return True, res.content
    except ApiError as e:
        return False, None

def __upload_s3(store, file_object, path):
    # Without this, s3 creates a new blank folder
    path = path.lstrip('/')
    client = boto3.client(
        's3',
        aws_access_key_id=store.endpoint__amazon_s3_access_key_id,
        aws_secret_access_key=store.endpoint__amazon_s3_access_secret_key
    )

    client.put_object(Bucket=store.endpoint__amazon_s3_bucket, Key=path, Body=file_object)

def __download_s3(account, file_path):
    path = file_path.lstrip('/')
    client = boto3.client(
        's3',
        aws_access_key_id=account.endpoint__amazon_s3_access_key_id,
        aws_secret_access_key=account.endpoint__amazon_s3_access_secret_key
    )

    try:
        object = client.get_object(Bucket=account.endpoint__amazon_s3_bucket, Key=path)
    except ClientError as e:
        return False, None
    return True, object["Body"].read()

def __upload_hosted_s3(email_address, file_object, path):
    # Without this, s3 creates a new blank folder
    path = "%s/%s" % (base64.encodestring(email_address), path.lstrip('/'))
    client = boto3.client(
        's3',
        aws_access_key_id=config__get("COUCHDROP_SERVICE__AWS_KEY"),
        aws_secret_access_key=config__get("COUCHDROP_SERVICE__AWS_SECRET")
    )

    client.put_object(Bucket=config__get("COUCHDROP_SERVICE__AWS_HOSTED_S3_BUCKET"), Key=path, Body=file_object)

def __download_hosted_s3(email_address, file_path):
    path = "%s/%s" % (base64.encodestring(email_address), file_path.lstrip('/'))
    client = boto3.client(
        's3',
        aws_access_key_id=config__get("COUCHDROP_SERVICE__AWS_KEY"),
        aws_secret_access_key=config__get("COUCHDROP_SERVICE__AWS_SECRET")
    )

    try:
        object = client.get_object(Bucket=config__get("COUCHDROP_SERVICE__AWS_HOSTED_S3_BUCKET"), Key=path)
    except ClientError as e:
        return False, None
    return True, object["Body"].read()


def __upload_webdav(store, file_object, path):
    webdav = easywebdav.connect(
        store.endpoint__webdav_hostname,
        username=store.endpoint__webdav_username,
        password=store.endpoint__webdav_password,
        path=store.endpoint__webdav_path,
        protocol=store.endpoint__webdav_protocol
    )

    directories = path.split("/")
    if len(directories) > 1:
        webdav.mkdirs("/".join(path.split("/")[0:-1]))
    webdav.upload(file_object, path)


def __download_webdav(store, file_path):
    path = file_path.lstrip('/')

    webdav = easywebdav.connect(
        store.endpoint__webdav_hostname,
        username=store.endpoint__webdav_username,
        password=store.endpoint__webdav_password,
        path=store.endpoint__webdav_path,
        protocol=store.endpoint__webdav_protocol
    )

    try:
        file_string = webdav.download(path)
        return True, file_string
    except OperationFailed as e:
        return False, None


@application.route("/manage/files/<file_id>/download", methods=["GET"])
def manage_download(file_id):
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    # Find the required file object
    file = flask.g.db_session.query(File).filter(File.account == token_object.account, File.id == file_id).scalar()
    if not file:
        return flask.jsonify(err="File not found"), 404

    url = ""
    account = flask.g.db_session.query(Account).filter(Account.username == token_object.account).scalar()
    if file.storage_engine == "s3":
        url = __generate_s3_url(account, file)
    elif file.storage_engine == "dropbox":
        url = __generate_dropbox_url(account, file)
    return flask.jsonify(url=url)


def __perform_email(account, file, path):
    # Path is something like: /email:to/michael@sphinix.com
    target_split = path.split("/")
    email = target_split[2]

    base64_encoded_file = base64.b64encode(file.read())
    mandrill__send_file__email(
        email, email, account.email_address, file.filename, base64_encoded_file
    )


def __record_audit(token, username, authenticaterd_user, path, storage_engine):
    audit_event = File()
    audit_event.id = str(uuid.uuid4())
    audit_event.token = token
    audit_event.account = username
    audit_event.filename = path
    audit_event.storage_engine = storage_engine
    audit_event.time = datetime.datetime.now()
    audit_event.authenticated_user = authenticaterd_user
    flask.g.db_session.add(audit_event)


@application.route("/push/upload/<token>", methods=["POST"])
def push_upload(token):
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object:
        return flask.jsonify(err="Token was not valid"), 403

    account = flask.g.db_session.query(Account).filter(Account.username == token_object.account).scalar()
    if not account:
        return flask.jsonify(err="Could not find account for token"), 403

    creds = flask.g.db_session.query(TempCredentials).filter(
        TempCredentials.account == token_object.account, TempCredentials.username == token_object.authenticated_user
    ).scalar()

    if "file" not in request.files:
        return flask.jsonify(err="File was not provided"), 500

    file = request.files['file']
    file_path = request.form.get("path")

    if "/" not in file_path:
        file_path = "/" + file_path

    if "/email:to" in file_path:
        __perform_email(account, file, file_path)
        __record_audit(token, account.username, token_object.authenticated_user, file_path, "email")
    else:
        storage_entries = flask.g.db_session.query(Storage).filter(
            Storage.account == token_object.account
        ).all()

        sorted_stores = []
        for store in storage_entries:
            sorted_stores.append(store)

        sorted_stores.sort(key=lambda x: len(x.path), reverse=True)
        for store in sorted_stores:
            if store.path in file_path:
                if store.permissions != "w" and store.permissions != "rw":
                    return flask.jsonify({"error": "Write permission is not allowed on this bucket"}), 403

                if creds:
                    if (creds.permissions_mode !="w" and creds.permissions_mode !="rw") or creds.permissions_path not in store.path:
                        return flask.jsonify({"error": "Credentials do not match requirements"}), 403

                if store.path != "/":
                    new_file_path = file_path.replace(store.path, "")
                else:
                    new_file_path = file_path

                if store.store_type == "dropbox":
                    __upload_dropbox(store, file, new_file_path)
                    __record_audit(token, account.username, token_object.authenticated_user, new_file_path, "dropbox")
                    break
                if store.store_type == "s3":
                    __upload_s3(store, file, new_file_path)
                    __record_audit(token, account.username, token_object.authenticated_user, new_file_path, "s3")
                    break
                if store.store_type == "hosted":
                    __upload_hosted_s3(account.email_address, file, new_file_path)
                    __record_audit(token, account.username, token_object.authenticated_user, new_file_path, "s3")
                    break
                if store.store_type == "webdav":
                    __upload_webdav(store, file, new_file_path)
                    __record_audit(token, account.username, token_object.authenticated_user, new_file_path, "webdav")
                    break
    return flask.jsonify({})


@application.route("/pull/download/<token>", methods=["POST"])
def pull_download(token):
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object:
        return flask.jsonify(err="Token was not valid"), 403

    account = flask.g.db_session.query(Account).filter(Account.username == token_object.account).scalar()
    if not account:
        return flask.jsonify(err="Could not find account for token"), 403

    creds = flask.g.db_session.query(TempCredentials).filter(
        TempCredentials.account == token_object.account, TempCredentials.username == token_object.authenticated_user
    ).scalar()

    file_path = request.form.get("path")
    storage_entries = flask.g.db_session.query(Storage).filter(
        Storage.account == token_object.account
    ).all()

    sorted_stores = []
    for store in storage_entries:
        sorted_stores.append(store)

    if "/" not in file_path:
        file_path = "/" + file_path

    sorted_stores.sort(key=lambda x: len(x.path), reverse=True)
    for store in sorted_stores:
        if store.path in file_path:
            if store.path != "/":
                new_file_path = file_path.replace(store.path, "")
            else:
                new_file_path = file_path

            if store.permissions != "r" and store.permissions != "rw":
                return flask.jsonify({"error": "Read permission is not allowed on this bucket"}), 403

            if creds:
                if (creds.permissions_mode !="r" and creds.permissions_mode !="rw") or creds.permissions_path not in store.path:
                    return flask.jsonify({"error": "Credentials do not match requirements"}), 403

            if store.store_type == "dropbox":
                success, binary_file_content = __download_dropbox(store, new_file_path)
                if success:
                    encoded_file = base64.b64encode(binary_file_content)
                    return flask.jsonify({"b64_content": encoded_file})
                else:
                    return flask.jsonify({"error": "Dropbox could not return the file: " + new_file_path}), 404

            if store.store_type == "s3":
                success, binary_file_content = __download_s3(store, new_file_path)
                if success:
                    encoded_file = base64.b64encode(binary_file_content)
                    return flask.jsonify({"b64_content": encoded_file})
                else:
                    return flask.jsonify({"error": "S3 could not return the file: " + new_file_path}), 404

            if store.store_type == "webdav":
                success, binary_file_content = __download_webdav(store, new_file_path)
                if success:
                    encoded_file = base64.b64encode(binary_file_content)
                    return flask.jsonify({"b64_content": encoded_file})
                else:
                    return flask.jsonify({"error": "Webdav could not return the file: " + new_file_path}), 404

            if store.store_type == "hosted":
                success, binary_file_content = __download_hosted_s3(account.email_address, new_file_path)
                if success:
                    encoded_file = base64.b64encode(binary_file_content)
                    return flask.jsonify({"b64_content": encoded_file})
                else:
                    return flask.jsonify({"error": "S3 could not return the file: " + new_file_path}), 404

    return flask.jsonify({})
