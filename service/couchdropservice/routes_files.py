import uuid

import boto3
import datetime
import flask
from dropbox import dropbox

from flask.globals import request

from couchdropservice import application
from couchdropservice.model import Account, PushToken, File


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
            "uploader": file.authenticated_user
        })
    return flask.jsonify(files=ret)


def __generate_dropbox_url(account, file):
    dbx = dropbox.Dropbox(account.endpoint__dropbox_access_token)
    return dbx.files_get_temporary_link("/" + file.filename).link


def __generate_s3_url(account, file):
    client = boto3.client(
        's3',
        aws_access_key_id=account.endpoint__amazon_s3_access_key_id,
        aws_secret_access_key=account.endpoint__amazon_s3_access_secret_key
    )

    url = client.generate_presigned_url(
        'get_object',
        Params={'Bucket': account.endpoint__amazon_s3_bucket, 'Key': file.filename},
        ExpiresIn=100
    )
    return url


def __upload_dropbox(account, file_object):
    dbx = dropbox.Dropbox(account.endpoint__dropbox_access_token)
    dbx.files_upload(file_object, "/" + file_object.filename)

def __upload_s3(account, file_object):
    client = boto3.client(
        's3',
        aws_access_key_id=account.endpoint__amazon_s3_access_key_id,
        aws_secret_access_key=account.endpoint__amazon_s3_access_secret_key
    )

    client.put_object(Bucket=account.endpoint__amazon_s3_bucket, Key=file_object.filename, Body=file_object)


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
    if account.endpoint__amazon_s3_enabled:
        url = __generate_s3_url(account, file)
    elif account.endpoint__dropbox_enabled:
        url = __generate_dropbox_url(account, file)
    return flask.jsonify(url=url)


@application.route("/push/upload/<token>", methods=["POST"])
def push_upload(token):
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object:
        return flask.jsonify(err="Token was not valid"), 403

    account = flask.g.db_session.query(Account).filter(Account.username == token_object.account).scalar()
    if not account:
        return flask.jsonify(err="Could not find account for token"), 403

    if "file" not in request.files:
        return flask.jsonify(err="File was not provided"), 500

    file = request.files['file']

    if account.endpoint__amazon_s3_enabled:
        __upload_s3(account, file)
    elif account.endpoint__dropbox_enabled:
        __upload_dropbox(account, file)

    audit_event = File()
    audit_event.id = str(uuid.uuid4())
    audit_event.token = token
    audit_event.account = account.username
    audit_event.filename = file.filename
    audit_event.time = datetime.datetime.now()
    audit_event.authenticated_user = token_object.authenticated_user
    flask.g.db_session.add(audit_event)

    return flask.jsonify({})
