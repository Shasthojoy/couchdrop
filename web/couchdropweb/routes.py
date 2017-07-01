import os

import flask
from flask import session, redirect, request, flash, render_template, current_app
from flask.ext.login import logout_user, login_user, login_required, current_user

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
                session["username"] = request.form.get("email")
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
    buckets = middleware.api__get_storage(flask.g.current_user.get_id())

    return render_template(
        "homepage.html", audit=audit, account=account, credentials=credentials, buckets=buckets
    )


@application.route("/credentials", methods=["GET"])
@login_required
def credentials():
    credentials = middleware.api__get_credentials(flask.g.current_user.get_id())
    account = middleware.api__get_account(flask.g.current_user.get_id())
    return render_template("credentials.html", credentials=credentials, account=account)


@application.route("/ajax/credentials", methods=["GET"])
@login_required
def credentials_ajax():
    account = middleware.api__get_account(flask.g.current_user.get_id())
    credentials = middleware.api__get_credentials(flask.g.current_user.get_id())
    return flask.jsonify(dict(credentials=credentials, account=account))


@application.route("/ajax/credentials", methods=["POST"])
@login_required
def credentials_ajax_save():
    middleware.api__get_credentials_save(flask.g.current_user.get_id(), request.json)
    return "OK"

@application.route("/ajax/credentials/rsakey", methods=["POST"])
@login_required
def credentials_ajax_save_main_rsa_key():
    account = middleware.api__get_account(flask.g.current_user.get_id())
    account["endpoint__valid_public_key"] = request.json.get("endpoint__valid_public_key")
    middleware.api__set_account(flask.g.current_user.get_id(), account)
    return "OK"


@application.route("/ajax/credentials", methods=["PUT"])
@login_required
def credentials_ajax_add():
    middleware.api__get_credentials_create(flask.g.current_user.get_id())
    return "OK"


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
        if request.form.get("password") and request.form.get("password") == request.form.get("password2"):
            account["password"] = request.form.get("password")

        account["email_address"] = request.form.get("email_address")
        middleware.api__set_account(flask.g.current_user.get_id(), account)
    return render_template("account.html", account=account)


@application.route("/buckets", methods=["GET"])
@login_required
def buckets():
    account = middleware.api__get_storage(flask.g.current_user.get_id())
    return render_template("buckets.html", account=account)


@application.route("/ajax/buckets", methods=["GET"])
@login_required
def ajax_buckets():
    buckets = middleware.api__get_storage(flask.g.current_user.get_id())
    return flask.jsonify(buckets=buckets)


@application.route("/ajax/buckets", methods=["PUT"])
@login_required
def ajax_buckets_put():
    middleware.api__put_storage(flask.g.current_user.get_id())
    return flask.jsonify({})


@application.route("/ajax/buckets/<id>", methods=["DELETE"])
@login_required
def ajax_buckets_delete(id):
    middleware.api__delete_storage(flask.g.current_user.get_id(), id)
    return flask.jsonify({})


@application.route("/ajax/buckets", methods=["POST"])
@login_required
def ajax_buckets_post():
    data = request.json
    for bucket in data:
        middleware.api__post_storage(flask.g.current_user.get_id(), bucket)
    return flask.jsonify({})


def get_dropbox_auth_flow(web_app_session):
    return DropboxOAuth2Flow(
        os.environ["COUCHDROP_WEB__DROPBOX_KEY"], os.environ["COUCHDROP_WEB__DROPBOX_SECRET"],
        os.environ["COUCHDROP_WEB__REDIRECT_URI"], web_app_session,
        "dropbox-auth-csrf-token"
    )


@application.route("/buckets/<id>/dropbox/activate")
@login_required
def dropbox_auth_start(id):

    authorize_url = get_dropbox_auth_flow(session).start(url_state=id)
    return redirect(authorize_url)


@application.route("/buckets/dropbox/activate/callback")
@login_required
def dropbox_auth_finish():
    account = middleware.api__get_account(flask.g.current_user.get_id())
    access_token, user_id, url_state = get_dropbox_auth_flow(session).finish(request.args)

    buckets = middleware.api__get_storage(flask.g.current_user.get_id())
    for bucket in buckets:
        if bucket.get("id") == url_state:
            bucket["endpoint__dropbox_access_token"] = access_token
            bucket["endpoint__dropbox_user_id"] = user_id
            bucket["store_type"] = "dropbox"
            middleware.api__post_storage(flask.g.current_user.get_id(), bucket)

    return redirect("/buckets")


@application.before_request
def before_request():
    if current_user.is_authenticated() and request.endpoint != 'login':
        flask.g.username = session.get("username")
