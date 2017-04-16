import os

from flask.app import Flask
from flask_assets import Environment
from flask_login import LoginManager
from webassets.bundle import Bundle

def config__get(key):
    return os.environ.get(key)


application = Flask(__name__, static_folder="content")
application.secret_key = config__get("COUCHDROP_WEB__FLASK_SESSION_SECRET")

login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = "login"


from couchdropweb import routes
