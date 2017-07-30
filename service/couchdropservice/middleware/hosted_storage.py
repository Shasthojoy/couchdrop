import base64

import boto3
from botocore.exceptions import ClientError

from couchdropservice import config__get
from couchdropservice.middleware.base_storage_provider import Store


class HostedStore(Store):
    def __init__(self, entity, email_address):
        super(HostedStore, self).__init__(entity, email_address)
        self.entity = entity
        self.email_address = email_address

    def upload(self, path, file_object):
        path = "%s/%s" % (base64.encodestring(self.email_address), path.lstrip('/'))
        client = boto3.client(
            's3',
            aws_access_key_id=config__get("COUCHDROP_SERVICE__AWS_KEY"),
            aws_secret_access_key=config__get("COUCHDROP_SERVICE__AWS_SECRET")
        )

        client.put_object(Bucket=config__get("COUCHDROP_SERVICE__AWS_HOSTED_S3_BUCKET"), Key=path, Body=file_object)


    def download(self, path):
        path = "%s/%s" % (base64.encodestring(self.email_address), path.lstrip('/'))
        client = boto3.client(
            's3',
            aws_access_key_id=config__get("COUCHDROP_SERVICE__AWS_KEY"),
            aws_secret_access_key=config__get("COUCHDROP_SERVICE__AWS_SECRET")
        )

        object = client.get_object(Bucket=config__get("COUCHDROP_SERVICE__AWS_HOSTED_S3_BUCKET"), Key=path)
        return True, object["Body"].read()
