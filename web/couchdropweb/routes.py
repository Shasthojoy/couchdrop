import base64
import json
import os

import flask
import requests
from flask import session, redirect, request, flash, render_template, current_app
from flask.ext.login import logout_user, login_user, login_required, current_user
from oauth2client.client import OAuth2WebServerFlow

from couchdropweb import application, login_manager

from couchdropweb import middleware
from couchdropweb.middleware import User

from dropbox import DropboxOAuth2Flow

from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage

from couchdropweb.middleware.google_credentials_storage import GoogleCredentailStorage


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


def __check_capture():
    verify_capture = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data=dict(secret=os.environ["COUCHDROP_WEB__RECAPTURE_SECRET"],
                  response=request.form.get("g-recaptcha-response"))
    )

    if verify_capture.status_code != 200:
        flash("Recapture failed, please try again")
        return False

    capture_data_dict = json.loads(verify_capture.text)
    if not capture_data_dict["success"]:
        flash("Recapture failed, please try again")
        return False

    return True


@application.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        try:
            # if not __check_capture():
            #     return redirect("/login")

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
    return render_template("login__login.html"), 403


@application.route("/resetpassword", methods=["GET"])
def resetpassword():
    return flask.render_template("login__resetpassword.html")


@application.route("/resetpassword", methods=["POST"])
def resetpassword_send():
    if not __check_capture():
        return redirect("/resetpassword")

    middleware.request_reset_password(
        request.form.get("real_email_address")
    )
    return flask.render_template("login__resetpassword_sent.html")


@application.route("/resetpassword/<code>", methods=["GET"])
def resetpassword_reset(code):
    return flask.render_template("login__resetpassword_reset.html")


@application.route("/resetpassword/<code>", methods=["POST"])
def resetpassword_reset_post(code):
    middleware.reset_password(
        code, request.form.get("password")
    )
    return redirect("/login")


@application.route("/register", methods=["GET"])
def register_get():
    return render_template("login__register.html")


@application.route("/register", methods=["POST"])
def register_save():
    # if not __check_capture():
    #     return redirect("/register")

    register_result = middleware.register(
        request.form.get("email"), request.form.get("password"), request.form.get("real_email_address"),
        request.form.get("subscription_type"), request.form.get("stripeToken")
    )

    if not register_result:
        flash("User creation failed, user already exists or another error was encountered")
        return redirect("/register")
    return redirect("/register/awaitingconfirm")


@application.route("/register/awaitingconfirm", methods=["GET"])
def register_awaiting_confirm():
    return render_template("login__register_email_sent.html")


@application.route("/register/awaitingconfirm/<confirm_code>")
def register_awaiting_confirm_confirm_code(confirm_code):
    account = middleware.register_confirm(confirm_code)
    if not account:
        return "FAILED"
    return redirect("/register/finish")


@application.route("/register/finish", methods=["GET"])
def register_finish():
    return render_template("login__register_finish.html")


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

    # If there is a subscription, check the stripe details to make sure its valid and then use this info
    subscription__status = False

    stripe_customer = account["stripe__customer"]
    for subscription in stripe_customer["subscriptions"]["data"]:
        if subscription["plan"]["name"] == account["subscription_type"]:
            subscription__status = subscription["status"]
    account["subscription_status"] = subscription__status

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


def __get_bucket(id):
    buckets = middleware.api__get_storage(flask.g.current_user.get_id())
    for bucket in buckets:
        if bucket.get("id") == id:
            return bucket
    return None


@application.route("/buckets/<id>/googledrive/activate")
@login_required
def googledrive_auth_start(id):
    flow = OAuth2WebServerFlow(
        client_id=os.environ["COUCHDROP_WEB__GOOGLE_DEV_CLIENT_ID"],
        client_secret=os.environ["COUCHDROP_WEB__GOOGLE_DEV_CLIENT_SECRET"],
        scope='https://www.googleapis.com/auth/drive.file',
        redirect_uri=os.environ["COUCHDROP_WEB__GOOGLE_DEV_REDIRECT_URL"],
        access_type="offline",
    )

    auth_uri = flow.step1_get_authorize_url(state=id)
    return redirect(auth_uri)


@application.route("/buckets/googledrive/activate/callback")
@login_required
def googledrive_auth_finish():
    bucket = __get_bucket(flask.request.args.get("state"))
    flow = OAuth2WebServerFlow(
        client_id=os.environ["COUCHDROP_WEB__GOOGLE_DEV_CLIENT_ID"],
        client_secret=os.environ["COUCHDROP_WEB__GOOGLE_DEV_CLIENT_SECRET"],
        scope='https://www.googleapis.com/auth/drive.file',
        redirect_uri=os.environ["COUCHDROP_WEB__GOOGLE_DEV_REDIRECT_URL"], access_type="offline",
    )

    credentials = flow.step2_exchange(flask.request.args.get("code"))
    bucket["endpoint__googledrive_credentials"] = credentials.to_json()
    middleware.api__post_storage(flask.g.current_user.get_id(), bucket)
    return redirect("/buckets")


@application.route("/buckets/<id>/dropbox/activate")
@login_required
def dropbox_auth_start(id):
    session["DROP_BOX_ACTIVATE_ID"] = id
    authorize_url = get_dropbox_auth_flow(session).start()
    return redirect(authorize_url)


@application.route("/buckets/dropbox/activate/callback")
@login_required
def dropbox_auth_finish():
    access_token, user_id, url_state = get_dropbox_auth_flow(session).finish(request.args)

    buckets = middleware.api__get_storage(flask.g.current_user.get_id())
    for bucket in buckets:
        if bucket.get("id") == session["DROP_BOX_ACTIVATE_ID"]:
            bucket["endpoint__dropbox_access_token"] = access_token
            bucket["endpoint__dropbox_user_id"] = user_id
            bucket["store_type"] = "dropbox"
            middleware.api__post_storage(flask.g.current_user.get_id(), bucket)

    return redirect("/buckets")


@application.route("/account/subscription", methods=["POST"])
@login_required
def account_subscription_save():
    subscription_type = request.form.get("subscription_type")
    stripe_token = request.form.get("stripeToken")

    middleware.api__update_subscription(flask.g.current_user.get_id(), subscription_type, stripe_token)
    return redirect("/account")


@application.before_request
def before_request():
    flask.g.stripe_token = os.environ["COUCHDROP_WEB__STRIPE_PUBLISHABLE_KEY"]

    if current_user.is_authenticated() and request.endpoint != 'login':
        flask.g.username = session.get("username")


@application.errorhandler(500)
def error():
    import traceback
    traceback.print_exc()
