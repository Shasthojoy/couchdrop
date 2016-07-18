import os
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from couchdropservice.model import Base


class BaseTester(unittest.TestCase):
    def init_db(self):
        connection = self.engine.connect()
        db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=connection))
        Base.query = db_session.query_property()
        Base.metadata.create_all(bind=connection)
        return db_session

    def close_db(self, blah):
        blah.flush()
        blah.commit()

    def setUp(self):
        os.system("rm /tmp/temp.db")

        from couchdropservice import application

        application.config['TESTING'] = True
        self.app = application.test_client()
        self.engine = create_engine("sqlite:////tmp/temp.db", convert_unicode=True)
        self.session = self.init_db()

        from flask.globals import current_app

        with application.app_context():
            current_app.init_db = self.init_db
            current_app.close_db = self.close_db

    def persist(self, objects):
        for object in objects:
            self.session.add(object)
            self.session.commit()
