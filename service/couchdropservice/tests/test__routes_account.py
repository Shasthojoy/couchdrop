import json
import os

from werkzeug.security import generate_password_hash

from couchdropservice.model import Account, PushToken, Storage
from couchdropservice.tests.base_tester import BaseTester


class RoutesAccount__TestCase(BaseTester):
    def test_register(self):
        rv = self.app.post(
            "/register",
            data={
                "username": "michael",
                "password": "password123",
                "email_address": "michael@couchdrop.io"
            }
        )

        assert rv.status_code == 200
        assert len(self.session.query(Account).all()) == 1

        created_account = self.session.query(Account).all()[0]
        assert created_account
        assert created_account.username == "michael"
        assert created_account.password
        assert created_account.email_address == "michael@couchdrop.io"

    def test_register_existing_account(self):
        account = Account()
        account.username = "michael"
        account.email_address = "michael@couchdrop.io"
        self.persist([account])

        rv = self.app.post(
            "/register",
            data={
                "username": "michael",
                "password": "password123",
                "email_address": "michael@couchdrop.io"
            }
        )

        assert rv.status_code == 403

    def test_authenticate__valid(self):
        account = Account()
        account.username = "michael"
        account.email_address = "michael@couchdrop.io"
        account.password = generate_password_hash("password")
        self.persist([account])

        rv = self.app.post(
            "/authenticate",
            data={
                "username": "michael",
                "password": "password",
            }
        )

        assert rv.status_code == 200
        assert json.loads(rv.data)["token"]

    def test_authenticate__get_pub__no_key(self):
        os.environ["COUCHDROP_SERVICE__SERVICE_TOKEN"] = "key"

        account = Account()
        account.username = "michael"
        account.email_address = "michael@couchdrop.io"
        self.persist([account])

        rv = self.app.post(
            "/authenticate/get/pub",
            data={
                "username": "michael",
                "service_token": "key",
            }
        )

        assert rv.status_code == 403

    def test_authenticate__get_pub__key(self):
        os.environ["COUCHDROP_SERVICE__SERVICE_TOKEN"] = "key"

        account = Account()
        account.username = "michael"
        account.email_address = "michael@couchdrop.io"
        account.endpoint__valid_public_key = "publickey"
        self.persist([account])

        rv = self.app.post(
            "/authenticate/get/pub",
            data={
                "username": "michael",
                "service_token": "key",
            }
        )

        assert rv.status_code == 200
        assert json.loads(rv.data) == {
            "public_key": "publickey"
        }

    def test_authenticate__get_pub__key_invalid_service_token(self):
        os.environ["COUCHDROP_SERVICE__SERVICE_TOKEN"] = "key"

        account = Account()
        account.username = "michael"
        account.email_address = "michael@couchdrop.io"
        account.endpoint__valid_public_key = "publickey"
        self.persist([account])

        rv = self.app.post(
            "/authenticate/get/pub",
            data={
                "username": "michael",
                "service_token": "dudes",
            }
        )

        assert rv.status_code == 403

    def test_authenticate__get_token(self):
        os.environ["COUCHDROP_SERVICE__SERVICE_TOKEN"] = "key"

        account = Account()
        account.username = "michael"
        account.email_address = "michael@couchdrop.io"
        self.persist([account])

        rv = self.app.post(
            "/authenticate/get/token",
            data={
                "username": "michael",
                "service_token": "key",
            }
        )

        assert rv.status_code == 200

    def test_authenticate__get_token__invalid(self):
        os.environ["COUCHDROP_SERVICE__SERVICE_TOKEN"] = "key"

        account = Account()
        account.username = "michael"
        account.email_address = "michael@couchdrop.io"
        self.persist([account])

        rv = self.app.post(
            "/authenticate/get/token",
            data={
                "username": "michael",
                "service_token": "invalidkey",
            }
        )

        assert rv.status_code == 403

    def test_authenticate__invalid_password(self):
        account = Account()
        account.username = "michael"
        account.email_address = "michael@couchdrop.io"
        account.password = generate_password_hash("dudes")
        self.persist([account])

        rv = self.app.post(
            "/authenticate",
            data={
                "username": "michael",
                "password": "password",
            }
        )

        assert rv.status_code == 403

    def test_authenticate__invalid_user(self):
        account = Account()
        account.username = "michael"
        account.email_address = "michael@couchdrop.io"
        account.password = generate_password_hash("password")
        self.persist([account])

        rv = self.app.post(
            "/authenticate",
            data={
                "username": "john",
                "password": "password",
            }
        )

        assert rv.status_code == 403


    def test_manage_account_storage(self):
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
        storage.endpoint__amazon_s3_access_key_id = "endpoint__amazon_s3_access_key_id"
        storage.endpoint__amazon_s3_access_secret_key = "endpoint__amazon_s3_access_secret_key"
        storage.endpoint__dropbox_access_token = "endpoint__dropbox_access_token"
        storage.endpoint__dropbox_user_id = "endpoint__dropbox_user_id"
        storage.store_type = "dropbox"

        self.persist([account, new_token, storage])

        rv = self.app.get(
            "/manage/account/storage?token=token1",
        )

        assert json.loads(rv.data) == {
            "storage": [
                {
                    "account": "michael",
                    "endpoint__amazon_s3_access_key_id": "endpoint__amazon_s3_access_key_id",
                    "endpoint__amazon_s3_access_secret_key": "endpoint__amazon_s3_access_secret_key",
                    "endpoint__dropbox_access_token": "endpoint__dropbox_access_token",
                    "endpoint__dropbox_user_id": "endpoint__dropbox_user_id",
                    "id": "id1",
                    "path": "/",
                    "store_type": "dropbox"
                }
            ]
        }


    def test_manage_account_storage_put(self):
        account = Account()
        account.username = "michael"
        account.endpoint__dropbox_enabled = True

        new_token = PushToken()
        new_token.account = "michael"
        new_token.token = "token1"
        new_token.admin = True

        self.persist([account, new_token])

        rv = self.app.put(
            "/manage/account/storage?token=token1",
        )

        rv = self.app.get(
            "/manage/account/storage?token=token1",
        )

        elem = json.loads(rv.data)["storage"]
        assert elem[0]["account"] == "michael"


    def test_manage_account_delete(self):
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
        storage.endpoint__amazon_s3_access_key_id = "endpoint__amazon_s3_access_key_id"
        storage.endpoint__amazon_s3_access_secret_key = "endpoint__amazon_s3_access_secret_key"
        storage.endpoint__dropbox_access_token = "endpoint__dropbox_access_token"
        storage.endpoint__dropbox_user_id = "endpoint__dropbox_user_id"
        storage.store_type = "dropbox"

        self.persist([account, new_token, storage])

        self.app.delete(
            "/manage/account/storage?token=token1", data=json.dumps({"id": "id1"})
        )

        rv = self.app.get(
            "/manage/account/storage?token=token1",
        )

        assert len(json.loads(rv.data)["storage"]) == 0

    def test_manage_account_storage_save(self):
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
        storage.path = ""
        storage.endpoint__amazon_s3_access_key_id = ""
        storage.endpoint__amazon_s3_access_secret_key = ""
        storage.endpoint__dropbox_access_token = ""
        storage.endpoint__dropbox_user_id = ""
        storage.store_type = ""

        self.persist([account, new_token, storage])

        rv = self.app.post(
            "/manage/account/storage?token=token1",
            data=json.dumps({
                "id": "id1",
                "path": "/path",
                "store_type": "dropbox"
            })
        )

        rv = self.app.get(
            "/manage/account/storage?token=token1",
        )

        assert json.loads(rv.data) == {
            "storage": [
                {
                    "account": "michael",
                    "endpoint__amazon_s3_access_key_id": "",
                    "endpoint__amazon_s3_access_secret_key": "",
                    "endpoint__dropbox_access_token": "",
                    "endpoint__dropbox_user_id": "",
                    "id": "id1",
                    "path": "/path",
                    "store_type": "dropbox"
                }
            ]
        }
