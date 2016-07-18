import flask

from flask.globals import current_app
from werkzeug.local import LocalProxy

from couchdropservice import application


def get_db_session():
    if hasattr(flask.g, "_db_session"):
        return flask.g._db_session
    else:
        flask.g._db_session = current_app.init_db()
    return flask.g._db_session


@application.before_request
def before():
    flask.g.db_session = LocalProxy(get_db_session)


@application.after_request
def after(f):
    flask.g.db_session.commit()
    current_app.close_db(flask.g.db_session)
    return f


@application.route("/status")
def status():
    return "OK"


@application.errorhandler(500)
def internal_server_error(error):
    print 'Server Error: %s' % (error)
    return error, 500
