from sqlalchemy import String, Column, DATETIME, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Account(Base):
    __tablename__ = "accounts"

    username = Column(String, primary_key=True)
    email_address = Column(String)
    password = Column(String)

    endpoint__amazon_s3_enabled = Column(Boolean)
    endpoint__amazon_s3_access_key_id = Column(String)
    endpoint__amazon_s3_access_secret_key = Column(String)
    endpoint__amazon_s3_bucket = Column(String)

    endpoint__dropbox_enabled = Column(Boolean)
    endpoint__dropbox_access_token = Column(String)
    endpoint__dropbox_user_id = Column(String)

    endpoint__valid_public_key = Column(String)

    def __init__(self):
        pass


class PushToken(Base):
    __tablename__ = "tokens"

    token = Column(String, primary_key=True)
    account = Column(String)
    authenticated_user = Column(String)
    admin = Column(Boolean)

    def __init__(self):
        pass


class File(Base):
    __tablename__ = "audit"

    id = Column(String, primary_key=True)
    token = Column(String)
    account = Column(String)
    filename = Column(String)
    time = Column(DATETIME)
    authenticated_user = Column(String)
    storage_engine = Column(String)

    def __init__(self):
        pass


class TempCredentials(Base):
    __tablename__ = "temp_credentials"

    username = Column(String, primary_key=True)
    password = Column(String)
    account = Column(String)

    public_key = Column(String)
    permissions_mode = Column(String)
    permissions_path = Column(String)


class Storage(Base):
    __tablename__ = "storage"

    id = Column(String, primary_key=True)
    account = Column(String)
    store_type = Column(String)
    path = Column(String)
    permissions = Column(String)

    endpoint__dropbox_access_token = Column(String)
    endpoint__dropbox_user_id = Column(String)
    endpoint__amazon_s3_access_key_id = Column(String)
    endpoint__amazon_s3_access_secret_key = Column(String)
    endpoint__amazon_s3_bucket = Column(String)

    endpoint__webdav_username = Column(String)
    endpoint__webdav_password = Column(String)
    endpoint__webdav_hostname = Column(String)
    endpoint__webdav_path = Column(String)
    endpoint__webdav_protocol = Column(String)
