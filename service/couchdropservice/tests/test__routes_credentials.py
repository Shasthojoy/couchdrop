import json

from couchdropservice.model import Account, PushToken, TempCredentials
from couchdropservice.tests.base_tester import BaseTester


class RoutesCredentials__TestCase(BaseTester):
    def test__create_credentials(self):
        # Create a token and Matching User

        account = Account()
        account.username = "michael"

        new_token = PushToken()
        new_token.account = account.username
        new_token.authenticated_user = account.username
        new_token.token = "token1"
        new_token.admin = True

        self.persist([account, new_token])

        rv = self.app.put(
            "/manage/credentials?token=token1",
            data={}
        )

        assert rv.status_code == 200
        assert len(self.session.query(TempCredentials).all()) == 1

        created_credentials = self.session.query(TempCredentials).all()[0]
        assert created_credentials
        assert created_credentials.account == "michael"
        assert created_credentials.username
        assert created_credentials.password


    def test__list_credentials(self):
        # Create a token and Matching User

        account = Account()
        account.username = "michael"

        new_token = PushToken()
        new_token.account = account.username
        new_token.authenticated_user = account.username
        new_token.token = "token1"
        new_token.admin = True

        credentials = TempCredentials()
        credentials.account = account.username
        credentials.username = "user1"
        credentials.password = "password1"

        self.persist([account, new_token, credentials])

        rv = self.app.get(
            "/manage/credentials?token=token1",
            data={}
        )

        assert rv.status_code == 200
        response = json.loads(rv.data)
        assert response["credentials"] == [
            {
                "password": "password1",
                "username": "user1"
            }
        ]


    def test__delete_credentials(self):
        # Create a token and Matching User

        account = Account()
        account.username = "michael"

        new_token = PushToken()
        new_token.account = account.username
        new_token.authenticated_user = account.username
        new_token.token = "token1"
        new_token.admin = True

        credentials = TempCredentials()
        credentials.account = account.username
        credentials.username = "user1"
        credentials.password = "password1"

        self.persist([account, new_token, credentials])

        rv = self.app.delete(
            "/manage/credentials/user1/delete?token=token1",
            data={}
        )

        assert rv.status_code == 200
        assert len(self.session.query(TempCredentials).all()) == 0


    def test__delete_credentials__invalid_account(self):
        # Create a token and Matching User

        account = Account()
        account.username = "michael"

        new_token = PushToken()
        new_token.account = account.username
        new_token.authenticated_user = account.username
        new_token.token = "token1"
        new_token.admin = True

        credentials = TempCredentials()
        credentials.account = "someotheruser"
        credentials.username = "user1"
        credentials.password = "password1"

        self.persist([account, new_token, credentials])

        rv = self.app.delete(
            "/manage/credentials/user1/delete?token=token1",
            data={}
        )

        # No delete operation performed
        assert len(self.session.query(TempCredentials).all()) == 1
