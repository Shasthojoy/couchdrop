import os

from flask.app import Flask
from flask_login import LoginManager

application = Flask(__name__, static_folder="content")
application.secret_key = "session_secret1122222222332321212"

def config__get(key):
    return os.environ.get(key)

from couchdropwebsite import routes
