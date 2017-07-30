import io
import httplib2

from googleapiclient import discovery
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
from oauth2client.client import Credentials

from couchdropservice.middleware.base_storage_provider import Store, StoreFileNotFound


class GoogleDriveStore(Store):
    def __init__(self, entity, email_address):
        super(GoogleDriveStore, self).__init__(entity, email_address)

    def __service(self):
        credentials = Credentials.new_from_json(self.entity.endpoint__googledrive_credentials)
        http = credentials.authorize(httplib2.Http())
        service = discovery.build('drive', 'v3', http=http)
        return service

    def find_googledrive_file(self, service, full_path):
        full_path_elems = filter(None, full_path.split("/"))

        last_parent = None
        for folder in full_path_elems:
            last_parent = self.find_googledrive_search(service, folder, parent_id=last_parent)
            if not last_parent:
                return None
        return last_parent

    def find_googledrive_create_folder(self, service, path, parent=None):
        file_metadata = {
            'name': path,
            'mimeType': 'application/vnd.google-apps.folder',
        }
        if parent:
            file_metadata['parents'] = [parent]

        file = service.files().create(
            body=file_metadata, fields='id'
        ).execute()
        return file.get("id")

    def find_googledrive_find_parent_folder(self, service, full_path, create_folders=False):
        full_path_elems = filter(None, full_path.split("/"))

        if len(full_path_elems) > 1:
            last_parent = None
            for folder in full_path_elems[0: len(full_path_elems) - 1]:
                new_parent = self.find_googledrive_search(service, folder, last_parent)
                if not new_parent:
                    if create_folders:
                        last_parent = self.find_googledrive_create_folder(service, folder, last_parent)
                    else:
                        return None
                else:
                    last_parent = new_parent
            return last_parent

    def find_googledrive_search(self, service, path, parent_id=None):
        page_token = None
        while True:
            q = "name='" + path + "'"
            if parent_id:
                q += " and '%s' in parents" % parent_id

            response = service.files().list(
                q=q,
                spaces='drive',
                fields='nextPageToken, files(id)',
                pageToken=page_token
            ).execute()

            for file in response.get('files', []):
                return file.get("id")

            page_token = response.get('nextPageToken', None)
            if page_token is None:
                break
        return None

    def __download_googledrive(self, full_path):
        service = self.__service()

        existing_file_id = self.find_googledrive_file(service, full_path)
        if not existing_file_id:
            raise StoreFileNotFound(full_path)

        request = service.files().get_media(fileId=existing_file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while done is False:
            status, done = downloader.next_chunk()
        return True, fh.getvalue()

    def __upload_googledrive(self, file_object, full_path):
        body = MediaIoBaseUpload(
            file_object.stream,
            mimetype='application/octet-stream',
            chunksize=1024 * 1024,
            resumable=True
        )
        passfile_metadata = {'name': file_object.filename}

        service = self.__service()
        existing_file_id = self.find_googledrive_file(service, full_path)
        if existing_file_id:
            service.files().update(
                fileId=existing_file_id,
                body=passfile_metadata,
                media_body=body,
                fields='id').execute()
        else:
            parent_id = self.find_googledrive_find_parent_folder(service, full_path, create_folders=True)
            if parent_id:
                passfile_metadata['parents'] = [parent_id]

            service.files().create(
                body=passfile_metadata,
                media_body=body,
                fields='id').execute()

    def upload(self, path, file_object):
        self.__upload_googledrive(file_object, full_path=path)

    def download(self, path):
        return self.__download_googledrive(full_path=path)
