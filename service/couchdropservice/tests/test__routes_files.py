import datetime
import json
from StringIO import StringIO

import requests
from mock import mock
from werkzeug.datastructures import FileStorage

from couchdropservice.middleware import easywebdav
from couchdropservice.model import PushToken, File, Account, Storage, TempCredentials
from couchdropservice.tests.base_tester import BaseTester


class RoutesFiles__TestCase(BaseTester):

    def test__get_files(self):
        # Create a token
        new_token = PushToken()
        new_token.account = "user1"
        new_token.token = "token1"
        new_token.admin = True

        file1 = File()
        file1.filename = "filename1.png"
        file1.id = "id1"
        file1.account = new_token.account
        file1.authenticated_user = "uploader"
        file1.time = datetime.datetime.now()

        self.persist([new_token, file1])

        rv = self.app.get(
            "/manage/files?token=token1",
            data={}
        )

        assert rv.status_code == 200

        files = json.loads(rv.data)
        assert len(files["files"]) == 1

        assert files["files"][0]["uploader"] == "uploader"
        assert files["files"][0]["filename"] == "filename1.png"
        assert files["files"][0]["id"] == "id1"


    @mock.patch('couchdropservice.routes_files.__generate_dropbox_url')
    def test__download_file__dropbox(self, __generate_dropbox_url):
        account = Account()
        account.username = "michael"
        account.endpoint__dropbox_enabled = True

        new_token = PushToken()
        new_token.account = "michael"
        new_token.token = "token1"
        new_token.admin = True

        file1 = File()
        file1.filename = "filename1.png"
        file1.id = "id1"
        file1.storage_engine = "dropbox"
        file1.account = new_token.account
        file1.authenticated_user = "uploader"
        file1.time = datetime.datetime.now()

        self.persist([account, new_token, file1])

        __generate_dropbox_url.return_value = "http://fakeurl"

        rv = self.app.get("/manage/files/id1/download?token=token1")
        assert rv.status_code == 200

        response = json.loads(rv.data)
        assert response["url"] == "http://fakeurl"


    @mock.patch('couchdropservice.routes_files.__generate_s3_url')
    def test__download_file__s3(self, __generate_s3_url):
        account = Account()
        account.username = "michael"
        account.endpoint__amazon_s3_enabled = True

        new_token = PushToken()
        new_token.account = "michael"
        new_token.token = "token1"
        new_token.admin = True

        file1 = File()
        file1.filename = "filename1.png"
        file1.id = "id1"
        file1.storage_engine = "s3"
        file1.account = new_token.account
        file1.authenticated_user = "uploader"
        file1.time = datetime.datetime.now()

        self.persist([account, new_token, file1])

        __generate_s3_url.return_value = "http://fakeurl"

        rv = self.app.get("/manage/files/id1/download?token=token1")
        assert rv.status_code == 200

        response = json.loads(rv.data)
        assert response["url"] == "http://fakeurl"


    def test__download_file__missing(self):
        account = Account()
        account.username = "michael"
        account.endpoint__amazon_s3_enabled = True

        new_token = PushToken()
        new_token.account = "michael"
        new_token.token = "token1"
        new_token.admin = True

        self.persist([account, new_token])

        rv = self.app.get("/manage/files/id1/download?token=token1")
        assert rv.status_code == 404


    def test__download_file__invalid_permissions(self):
        account = Account()
        account.username = "michael"
        account.endpoint__amazon_s3_enabled = True

        new_token = PushToken()
        new_token.account = "michael"
        new_token.token = "token1"
        new_token.admin = True

        file1 = File()
        file1.filename = "filename1.png"
        file1.id = "id1"
        file1.account = "random_account"
        file1.authenticated_user = "uploader"
        file1.time = datetime.datetime.now()

        self.persist([account, new_token, file1])

        rv = self.app.get("/manage/files/id1/download?token=token1")
        print rv.data
        assert rv.status_code == 404


    @mock.patch('couchdropservice.routes_files.__upload_s3')
    def test__upload_file__s3(self, __upload_s3):
        account = Account()
        account.username = "michael"
        account.endpoint__amazon_s3_enabled = True

        new_token = PushToken()
        new_token.account = "michael"
        new_token.token = "token1"
        new_token.admin = True

        storage = Storage()
        storage.id = "id1"
        storage.account = "michael"
        storage.path = "/"
        storage.endpoint__amazon_s3_access_key_id = ""
        storage.endpoint__amazon_s3_access_secret_key = ""
        storage.endpoint__dropbox_access_token = ""
        storage.endpoint__dropbox_user_id = ""
        storage.store_type = "s3"
        storage.permissions = "rw"

        self.persist([account, new_token, storage])

        resp = self.app.post(
            '/push/upload/token1',
            data = {
                'file': (StringIO('my file contents'), 'hello world.txt'),
                'path': '/dudes/path/hello world.txt'
            }
        )

        assert resp.status_code == 200
        assert len(self.session.query(File).all()) == 1
        assert __upload_s3.called == 1
        __upload_s3.assert_called_with(mock.ANY, mock.ANY, '/dudes/path/hello world.txt')



    @mock.patch('couchdropservice.routes_files.__upload_dropbox')
    def test__upload_file__dropbox(self, __upload_dropbox):
        account = Account()
        account.username = "michael"
        account.endpoint__dropbox_enabled = True

        new_token = PushToken()
        new_token.account = "michael"
        new_token.token = "token1"
        new_token.admin = True

        storage = Storage()
        storage.id = "id1"
        storage.account = "michael"
        storage.path = "/"
        storage.endpoint__amazon_s3_access_key_id = ""
        storage.endpoint__amazon_s3_access_secret_key = ""
        storage.endpoint__dropbox_access_token = ""
        storage.endpoint__dropbox_user_id = ""
        storage.store_type = "dropbox"
        storage.permissions = "rw"

        self.persist([account, new_token, storage])

        resp = self.app.post(
            '/push/upload/token1',
            data = {
                'file': (StringIO('my file contents'), 'hello world.txt'),
                'path': "/dudes/path/hello world.txt"
            }
        )

        assert resp.status_code == 200
        assert len(self.session.query(File).all()) == 1
        assert __upload_dropbox.called == 1
        __upload_dropbox.assert_called_with(mock.ANY, mock.ANY, '/dudes/path/hello world.txt')


    @mock.patch('couchdropservice.routes_files.__upload_dropbox')
    @mock.patch('couchdropservice.routes_files.__upload_s3')
    def test__upload_file__choose_path(self, __upload_s3, __upload_dropbox):
        account = Account()
        account.username = "michael"
        account.endpoint__dropbox_enabled = True

        new_token = PushToken()
        new_token.account = "michael"
        new_token.token = "token1"
        new_token.admin = True

        storage = Storage()
        storage.id = "id1"
        storage.account = "michael"
        storage.path = "/dropbox/path"
        storage.store_type = "dropbox"
        storage.permissions = "rw"

        storage2 = Storage()
        storage2.id = "id2"
        storage2.account = "michael"
        storage2.path = "/s3/path"
        storage2.store_type = "s3"
        storage2.permissions = "rw"

        storage3 = Storage()
        storage3.id = "id3"
        storage3.account = "michael"
        storage3.path = "/"
        storage3.store_type = "dropbox"
        storage3.permissions = "rw"

        self.persist([account, new_token, storage, storage2, storage3])

        resp = self.app.post(
            '/push/upload/token1',
            data = {
                'file': (StringIO('my file contents'), 'hello world.txt'),
                'path': "/s3/path/hello world.txt"
            }
        )

        assert resp.status_code == 200
        assert len(self.session.query(File).all()) == 1
        assert __upload_s3.called == 1
        __upload_s3.assert_called_with(mock.ANY, mock.ANY, '/hello world.txt')


    @mock.patch('couchdropservice.routes_files.__upload_dropbox')
    def test__upload_file__dropbox_nopath(self, __upload_dropbox):
        account = Account()
        account.username = "michael"
        account.endpoint__dropbox_enabled = True

        new_token = PushToken()
        new_token.account = "michael"
        new_token.token = "token1"
        new_token.admin = True

        storage = Storage()
        storage.id = "id1"
        storage.account = "michael"
        storage.path = "/"
        storage.endpoint__amazon_s3_access_key_id = ""
        storage.endpoint__amazon_s3_access_secret_key = ""
        storage.endpoint__dropbox_access_token = ""
        storage.endpoint__dropbox_user_id = ""
        storage.store_type = "dropbox"
        storage.permissions = "rw"

        self.persist([account, new_token, storage])

        resp = self.app.post(
            '/push/upload/token1',
            data = {
                'file': (StringIO('my file contents'), 'hello world.txt'),
                'path': "/hello world.txt"
            }
        )

        assert resp.status_code == 200
        assert len(self.session.query(File).all()) == 1
        assert __upload_dropbox.called == 1
        __upload_dropbox.assert_called_with(mock.ANY, mock.ANY, '/hello world.txt')


    @mock.patch('couchdropservice.routes_files.__upload_dropbox')
    def test__upload_file__dropbox__temp_user(self, __upload_dropbox):
        account = Account()
        account.username = "michael"
        account.endpoint__dropbox_enabled = True

        credentials = TempCredentials()
        credentials.account = "michael"
        credentials.username = "user-123"
        credentials.permissions_mode= "w"
        credentials.permissions_path= "/"

        new_token = PushToken()
        new_token.account = "michael"
        new_token.token = "token1"
        new_token.admin = False
        new_token.authenticated_user = "user-123"

        storage = Storage()
        storage.id = "id1"
        storage.account = "michael"
        storage.path = "/"
        storage.endpoint__amazon_s3_access_key_id = ""
        storage.endpoint__amazon_s3_access_secret_key = ""
        storage.endpoint__dropbox_access_token = ""
        storage.endpoint__dropbox_user_id = ""
        storage.store_type = "dropbox"
        storage.permissions = "rw"

        self.persist([account, new_token, storage, credentials])

        resp = self.app.post(
            '/push/upload/token1',
            data = {
                'file': (StringIO('my file contents'), 'hello world.txt'),
                'path': "/hello world.txt"
            }
        )

        assert resp.status_code == 200
        assert len(self.session.query(File).all()) == 1
        assert __upload_dropbox.called == 1
        __upload_dropbox.assert_called_with(mock.ANY, mock.ANY, '/hello world.txt')


    @mock.patch('couchdropservice.routes_files.__upload_dropbox')
    def test__upload_file__dropbox__temp_user__wrong_permissions(self, __upload_dropbox):
        account = Account()
        account.username = "michael"
        account.endpoint__dropbox_enabled = True

        credentials = TempCredentials()
        credentials.account = "michael"
        credentials.username = "user-123"
        credentials.permissions_mode= "r"
        credentials.permissions_path= "/"

        new_token = PushToken()
        new_token.account = "michael"
        new_token.token = "token1"
        new_token.admin = False
        new_token.authenticated_user = "user-123"

        storage = Storage()
        storage.id = "id1"
        storage.account = "michael"
        storage.path = "/"
        storage.endpoint__amazon_s3_access_key_id = ""
        storage.endpoint__amazon_s3_access_secret_key = ""
        storage.endpoint__dropbox_access_token = ""
        storage.endpoint__dropbox_user_id = ""
        storage.store_type = "dropbox"
        storage.permissions = "rw"

        self.persist([account, new_token, storage, credentials])

        resp = self.app.post(
            '/push/upload/token1',
            data = {
                'file': (StringIO('my file contents'), 'hello world.txt'),
                'path': "/hello world.txt"
            }
        )

        assert resp.status_code == 403
        assert len(self.session.query(File).all()) == 0
        assert __upload_dropbox.called == 0


    @mock.patch('couchdropservice.routes_files.__upload_dropbox')
    def test__upload_file__dropbox__temp_user__wrong_permissions_path(self, __upload_dropbox):
        account = Account()
        account.username = "michael"
        account.endpoint__dropbox_enabled = True

        credentials = TempCredentials()
        credentials.account = "michael"
        credentials.username = "user-123"
        credentials.permissions_mode= "w"
        credentials.permissions_path= "/dudes"

        new_token = PushToken()
        new_token.account = "michael"
        new_token.token = "token1"
        new_token.admin = False
        new_token.authenticated_user = "user-123"

        storage = Storage()
        storage.id = "id1"
        storage.account = "michael"
        storage.path = "/"
        storage.endpoint__amazon_s3_access_key_id = ""
        storage.endpoint__amazon_s3_access_secret_key = ""
        storage.endpoint__dropbox_access_token = ""
        storage.endpoint__dropbox_user_id = ""
        storage.store_type = "dropbox"
        storage.permissions = "rw"

        self.persist([account, new_token, storage, credentials])

        resp = self.app.post(
            '/push/upload/token1',
            data = {
                'file': (StringIO('my file contents'), 'hello world.txt'),
                'path': "/hello world.txt"
            }
        )

        assert resp.status_code == 403
        assert len(self.session.query(File).all()) == 0
        assert __upload_dropbox.called == 0

