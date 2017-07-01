import json
import uuid

import flask

from flask.globals import request

from couchdropservice import application
from couchdropservice.model import Account, PushToken, TempCredentials


@application.route("/manage/credentials", methods=["GET"])
def manage_credentials():
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    credentials = flask.g.db_session.query(TempCredentials).filter(
        TempCredentials.account == token_object.account).all()
    ret = []
    for credential in credentials:
        ret.append({
            "username": credential.username,
            "password": credential.password,

            "public_key": credential.public_key,
            "permissions_mode": credential.permissions_mode,
            "permissions_path": credential.permissions_path,
        })
    return flask.jsonify(credentials=ret)


@application.route("/manage/credentials", methods=["PUT"])
def manage_credentials_insert():
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    account = flask.g.db_session.query(Account).filter(Account.username == token_object.account).scalar()
    new = TempCredentials()
    new.account = account.username

    new.username = "user-" + str(uuid.uuid1()).split("-")[0]
    new.password = str(uuid.uuid1()).split("-")[0]
    new.permissions_mode= "w"
    new.permissions_path= "/"

    flask.g.db_session.add(new)
    return flask.jsonify({})


@application.route("/manage/credentials", methods=["POST"])
def manage_credentials_update():
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    data = json.loads(request.data)

    # account = flask.g.db_session.query(Account).filter(Account.username == token_object.account).scalar()
    credential = flask.g.db_session.query(TempCredentials).filter(
        Account.username == token_object.account, TempCredentials.username == data.get("username")
    ).scalar()

    credential.password = data.get("password")
    credential.public_key = data.get("public_key")
    credential.permissions_mode= data.get("permissions_mode")
    credential.permissions_path= data.get("permissions_path")
    return flask.jsonify({})


@application.route("/manage/credentials/<username>/delete", methods=["DELETE"])
def manage_credentials_delete(username):
    token = request.args.get("token")
    token_object = flask.g.db_session.query(PushToken).filter(PushToken.token == token).scalar()
    if not token_object or not token_object.admin:
        return flask.jsonify(err="Token was not valid"), 403

    flask.g.db_session.query(TempCredentials).filter(
        TempCredentials.username == username,
        TempCredentials.account == token_object.account
    ).delete()
    return flask.jsonify({})
