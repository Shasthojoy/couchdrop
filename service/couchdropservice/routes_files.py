import base64
import io
import uuid

import boto3
import datetime
import flask
import httplib2
from botocore.exceptions import ClientError
from dropbox import dropbox
from dropbox.exceptions import ApiError

from flask.globals import request
from googleapiclient import discovery
from googleapiclient.http import MediaFileUpload, MediaIoBaseUpload, MediaIoBaseDownload
from io import BytesIO
from oauth2client.client import Credentials

from couchdropservice import application, config__get
from couchdropservice.middleware.dropbox_api import DropboxStore
from couchdropservice.middleware.easywebdav import OperationFailed
from couchdropservice.middleware.email_sender import mandrill__send_file__email
from couchdropservice.middleware.googledrive_api import GoogleDriveStore
from couchdropservice.middleware.hosted_storage import HostedStore
from couchdropservice.middleware.s3_storage import S3Store
from couchdropservice.middleware.webdav_api import WebdavStore
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
            "uploader": file.authenticated_user,

            "storage_engine_id": file.storage_engine_id,
            "event_type": file.event_type,
            "ip_address": file.ip_address,
            "success": file.success,
            "additional_info": file.additional_info
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


def __record_audit(token, username, authenticated_user, path, storage_engine, storage_engine_id, event_type, ip_address,
                   success, additional_info=""):
    audit_event = File()
    audit_event.id = str(uuid.uuid4())
    audit_event.token = token
    audit_event.account = username
    audit_event.filename = path
    audit_event.storage_engine = storage_engine
    audit_event.time = datetime.datetime.now()
    audit_event.authenticated_user = authenticated_user
    audit_event.storage_engine_id = storage_engine_id
    audit_event.event_type = event_type
    audit_event.ip_address = ip_address
    audit_event.success = success
    audit_event.additional_info = additional_info
    flask.g.db_session.add(audit_event)


def __get_storage_provider(email_address, store, type):
    if type == "googledrive":
        return GoogleDriveStore(store, email_address)
    if type == "dropbox":
        return DropboxStore(store, email_address)
    if type == "webdav":
        return WebdavStore(store, email_address)
    if type == "s3":
        return S3Store(store, email_address)
    if type == "hosted":
        return HostedStore(store, email_address)
    return None


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
        __record_audit(
            token, account.username,
            token_object.authenticated_user, file_path,
            "email",
            None,
            "upload",
            "",
            True
        )
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
                    if (creds.permissions_mode != "w" and creds.permissions_mode != "rw") or creds.permissions_path not in store.path:
                        __record_audit(token,
                                       account.username,
                                       token_object.authenticated_user,
                                       file_path,
                                       store.store_type,
                                       None,
                                       "upload",
                                       "",
                                       False,
                                       "Credentials do not match requirements"
                                       )

                        return flask.jsonify({"error": "Credentials do not match requirements"}), 403

                if store.path != "/":
                    new_file_path = file_path.replace(store.path, "")
                else:
                    new_file_path = file_path

                try:
                    storage_provider = __get_storage_provider(account.email_address, store, store.store_type)
                    storage_provider.upload(new_file_path, file)

                    __record_audit(
                        token, account.username,
                        token_object.authenticated_user,
                        file_path,
                        store.store_type,
                        store.id,
                        "upload",
                        "",
                        True
                    )

                except Exception as e:
                    error_message = "Unknown error from storage engine, %s" % str(e)
                    __record_audit(
                        token, account.username,
                        token_object.authenticated_user, file_path,
                        "email", None,
                        "upload", "", False,
                        error_message
                    )

                    return flask.jsonify({"error": error_message}), 403
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
                __record_audit(
                    token, account.username,
                    token_object.authenticated_user,
                    file_path,
                    store.store_type,
                    store.id,
                    "download",
                    "",
                    False,
                    "Read permission is not allowed on this bucket"
                )

                return flask.jsonify({"error": "Read permission is not allowed on this bucket"}), 403

            if creds:
                if (creds.permissions_mode != "r"
                    and creds.permissions_mode != "rw") or creds.permissions_path not in store.path:
                    __record_audit(
                        token, account.username,
                        token_object.authenticated_user,
                        file_path,
                        store.store_type,
                        store.id,
                        "download",
                        "",
                        False,
                        "Credentials do not match requirements"
                    )

                    return flask.jsonify({"error": "Credentials do not match requirements"}), 403
            try:
                storage_provider = __get_storage_provider(account.email_address, store, store.store_type)
                success, binary_file_content = storage_provider.download(new_file_path)
                encoded_file = base64.b64encode(binary_file_content)
                __record_audit(
                    token, account.username,
                    token_object.authenticated_user,
                    file_path,
                    store.store_type,
                    store.id,
                    "download",
                    "",
                    True
                )
                return flask.jsonify({"b64_content": encoded_file})

            except Exception as e:
                error_message = "Unknown error from storage engine, %s" % str(e)
                __record_audit(
                    token, account.username,
                    token_object.authenticated_user,
                    file_path,
                    store.store_type,
                    store.id,
                    "download",
                    "",
                    False,
                    error_message
                )

                return flask.jsonify({"error": error_message}), 403

    return flask.jsonify({})
