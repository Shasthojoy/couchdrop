import json
from werkzeug.security import generate_password_hash

from couchdropservice.model import Account
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
