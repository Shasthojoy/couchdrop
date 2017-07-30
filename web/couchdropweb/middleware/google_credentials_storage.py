import json

from oauth2client.client import Storage as BaseStorage
from oauth2client.client import Credentials


class GoogleCredentailStorage(BaseStorage):
    def __init__(self, entity):
        self.couchdrop_storage_entity = entity

    def locked_get(self):
        credentials = None
        try:
            credentials = Credentials.new_from_json(self.couchdrop_storage_entity["google_credentials"])
            credentials.set_store(self)

        except ValueError as e:
            print "ERROR while request for google credentials. Err: %s" % (str(e))
            raise Exception("Failed to retrieve google credentials")
        return credentials

    def locked_put(self, credentials):
        self.couchdrop_storage_entity["google_credentials"] = credentials.to_json()

    def locked_delete(self):
        self.couchdrop_storage_entity["google_credentials"] = json.dumps({})
