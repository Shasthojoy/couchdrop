from dropbox import dropbox

from couchdropservice.middleware.base_storage_provider import Store


class DropboxStore(Store):
    def __init__(self, entity, email_address):
        super(DropboxStore, self).__init__(entity, email_address)
        self.entity = entity

    def upload(self, path, file_object):
        dbx = dropbox.Dropbox(self.entity.endpoint__dropbox_access_token)
        dbx.files_upload(file_object, path)

    def download(self, path):
        dbx = dropbox.Dropbox(self.entity.endpoint__dropbox_access_token)
        md, res = dbx.files_download(path)
        return True, res.content

