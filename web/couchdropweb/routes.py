import os

import flask
from flask import session, redirect, request, flash, render_template, current_app
from flask.ext.login import logout_user, login_user, login_required

from couchdropweb import application, login_manager

from couchdropweb import middleware
from couchdropweb.middleware import User

from dropbox import DropboxOAuth2Flow


@application.route("/logout")
def logout():
    session.clear()
    logout_user()
    return redirect("/")


@login_manager.user_loader
def load_user(userid):
    if not hasattr(flask.g, "current_user"):
        flask.g.current_user = User(userid)
    return flask.g.current_user


@application.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        try:
            authentication_token = middleware.authenticate(request.form.get("email"), request.form.get("password"))
            if authentication_token is not None:
                setattr(current_app, "current_user", User(authentication_token))
                login_user(User(authentication_token))
                return redirect("/")
            else:
                flash("login_invalid_username_password")
                return redirect("/login")
        except Exception as e:
            flash("login_invalid_username_password")
            return redirect("/login")
    return render_template("login.html"), 403


@application.route("/register", methods=["POST"])
def register():
    middleware.register(request.form.get("email"), request.form.get("password"), request.form.get("real_email_address"))
    return redirect("/login")


@application.route("/status")
def status():
    return "OK"


@application.route("/")
@login_required
def home():
    account = middleware.api__get_account(flask.g.current_user.get_id())
    audit = middleware.api__get_audit(flask.g.current_user.get_id())
    credentials = middleware.api__get_credentials(flask.g.current_user.get_id())

    return render_template("homepage.html", audit=audit, account=account, credentials=credentials)


@application.route("/credentials")
@login_required
def credentials():
    credentials = middleware.api__get_credentials(flask.g.current_user.get_id())
    return render_template("credentials.html", credentials=credentials)


@application.route("/credentials/create")
@login_required
def credentials_create():
    middleware.api__get_credentials_create(flask.g.current_user.get_id())
    return redirect("/credentials")


@application.route("/credentials/<username>/delete")
@login_required
def credentials_username(username):
    middleware.api__get_credentials_delete(flask.g.current_user.get_id(), username)
    return redirect("/credentials")


@application.route("/download/<file_id>")
def downloadfile(file_id):
    return redirect(middleware.api__get_filelink(file_id, flask.g.current_user.get_id()))


@application.route("/account", methods=["POST", "GET"])
@login_required
def account():
    account = middleware.api__get_account(flask.g.current_user.get_id())
    if request.method == "POST":
        if request.form.get("password") == request.form.get("password2"):
            account["password"] = request.form.get("password")

        account["email_address"] = request.form.get("email_address")
        account["endpoint__valid_public_key"] = request.form.get("endpoint__valid_public_key")
        middleware.api__set_account(flask.g.current_user.get_id(), account)
    return render_template("account.html", account=account)


@application.route("/buckets", methods=["POST", "GET"])
@login_required
def buckets():
    account = middleware.api__get_account(flask.g.current_user.get_id())
    if request.method == "POST":
        account["endpoint__dropbox_enabled"] = request.form.get("endpoint__dropbox_enabled") == "on"
        account["endpoint__amazon_s3_enabled"] = request.form.get("endpoint__amazon_s3_enabled") == "on"
        middleware.api__set_account(flask.g.current_user.get_id(), account)

        if account["endpoint__amazon_s3_enabled"]:
            account["endpoint__dropbox_enabled"] = False
            account["endpoint__amazon_s3_access_key_id"] = request.form.get("endpoint__amazon_s3_access_key_id")
            account["endpoint__amazon_s3_access_secret_key"] = request.form.get("endpoint__amazon_s3_access_secret_key")
            account["endpoint__amazon_s3_bucket"] = request.form.get("endpoint__amazon_s3_bucket")
            middleware.api__set_account(flask.g.current_user.get_id(), account)

        elif account["endpoint__dropbox_enabled"]:
            return redirect("/buckets/dropbox/activate")
    return render_template("buckets.html", account=account)


@application.route("/upload")
@login_required
def upload():
    return render_template("upload.html")


def get_dropbox_auth_flow(web_app_session):
    return DropboxOAuth2Flow(
        os.environ["COUCHDROP_WEB__DROPBOX_KEY"], os.environ["COUCHDROP_WEB__DROPBOX_SECRET"],
        os.environ["COUCHDROP_WEB__REDIRECT_URI"], web_app_session,
        "dropbox-auth-csrf-token"
    )


@application.route("/buckets/dropbox/activate")
@login_required
def dropbox_auth_start():
    authorize_url = get_dropbox_auth_flow(session).start()
    return redirect(authorize_url)


@application.route("/buckets/dropbox/activate/callback")
@login_required
def dropbox_auth_finish():
    account = middleware.api__get_account(flask.g.current_user.get_id())
    access_token, user_id, url_state = get_dropbox_auth_flow(session).finish(request.args)
    if access_token and user_id:
        account["endpoint__amazon_s3_enabled"] = False
        account["endpoint__dropbox_enabled"] = True
        account["endpoint__dropbox_access_token"] = access_token
        account["endpoint__dropbox_user_id"] = user_id
        middleware.api__set_account(flask.g.current_user.get_id(), account)
    return redirect("/buckets")
