from couchdropservice.middleware import easywebdav
from couchdropservice.middleware.base_storage_provider import Store
from couchdropservice.middleware.easywebdav import OperationFailed


class WebdavStore(Store):
    def __init__(self, entity, email_address):
        super(WebdavStore, self).__init__(entity, email_address)
        self.entity = entity

    def upload(self, path, file_object):
        webdav = easywebdav.connect(
            self.entity.endpoint__webdav_hostname,
            username=self.entity.endpoint__webdav_username,
            password=self.entity.endpoint__webdav_password,
            path=self.entity.endpoint__webdav_path,
            protocol=self.entity.endpoint__webdav_protocol
        )

        directories = path.split("/")
        if len(directories) > 1:
            webdav.mkdirs("/".join(path.split("/")[0:-1]))
        webdav.upload(file_object, path)


    def download(self, path):
        path = path.lstrip('/')

        webdav = easywebdav.connect(
            self.entity.endpoint__webdav_hostname,
            username=self.entity.endpoint__webdav_username,
            password=self.entity.endpoint__webdav_password,
            path=self.entity.endpoint__webdav_path,
            protocol=self.entity.endpoint__webdav_protocol
        )

        file_string = webdav.download(path)
        return True, file_string
