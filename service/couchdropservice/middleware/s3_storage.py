import boto3
from botocore.exceptions import ClientError

from couchdropservice.middleware.base_storage_provider import Store


class S3Store(Store):
    def __init__(self, entity, email_address):
        super(S3Store, self).__init__(entity, email_address)
        self.entity = entity

    def upload(self, path, file_object):
        path = path.lstrip('/')
        client = boto3.client(
            's3',
            aws_access_key_id=self.entity.endpoint__amazon_s3_access_key_id,
            aws_secret_access_key=self.entity.endpoint__amazon_s3_access_secret_key
        )

        client.put_object(Bucket=self.entity.endpoint__amazon_s3_bucket, Key=path, Body=file_object)


    def download(self, path):
        path = path.lstrip('/')
        client = boto3.client(
            's3',
            aws_access_key_id=self.entity.endpoint__amazon_s3_access_key_id,
            aws_secret_access_key=self.entity.endpoint__amazon_s3_access_secret_key
        )

        object = client.get_object(Bucket=self.entity.endpoint__amazon_s3_bucket, Key=path)
        return True, object["Body"].read()
