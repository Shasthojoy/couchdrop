from flask.app import Flask
from flask.globals import current_app
from multiprocessing import Lock
import os
from sqlalchemy.engine import create_engine
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.orm.session import sessionmaker

application = Flask(__name__)

def config__get(key):
    return os.environ.get(key)

lock = Lock()

def init_db():
    engine = create_engine(
        config__get("COUCHDROP_SERVICE__SQLALCHEMY_DATABASE_URI"),
        convert_unicode=True,
        pool_size=int(config__get("COUCHDROP_SERVICE__SQLALCHEMY_POOLSIZE_MAX")),
        pool_recycle=3600
    )

    with lock:
        connection = engine.connect()
    session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=connection))
    return session


def close_db(db_session):
    db_session.flush()
    db_session.commit()
    db_session.close()
    db_session.bind.close()


with application.test_request_context():
    current_app.init_db = init_db
    current_app.close_db = close_db

    from couchdropservice import routes
    from couchdropservice import routes_account
    from couchdropservice import routes_credentials
    from couchdropservice import routes_files
