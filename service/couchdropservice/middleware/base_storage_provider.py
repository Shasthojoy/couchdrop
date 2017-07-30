class StoreInvalidPermissions(Exception):
    def __init__(self, *args, **kwargs):
        super(StoreInvalidPermissions, self).__init__(*args, **kwargs)


class StoreFileNotFound(Exception):
    def __init__(self, *args, **kwargs):
        super(StoreFileNotFound, self).__init__(*args, **kwargs)

    def __str__(self):
        return "Could not find file"

class Store(object):
    def __init__(self, entity, email_address):
        self.entity = entity
        self.email_address = email_address

    def upload(self, path, file_object):
        pass

    def download(self, path):
        pass
