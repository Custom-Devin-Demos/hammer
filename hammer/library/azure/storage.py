"""
Azure storage accounts public blob access checks and remediation.
"""
import pathlib
import logging


from datetime import datetime, timezone
from library.utility import jsonDumps
from library.aws.s3 import S3Operations
from library.azure.utility import parse_resource_id


# container public access levels which allow anonymous read access
PUBLIC_ACCESS_LEVELS = ("Blob", "Container")
# error codes of Azure management API meaning missing permissions
ACCESS_DENIED_CODES = ("AuthorizationFailed", "AuthorizationPermissionMismatch", "Forbidden")


def access_level(value):
    """
    :param value: container public access level as Azure SDK returns (`PublicAccess` enum, str or None)

    :return: string with access level ("Blob", "Container", "None")
    """
    if value is None:
        return "None"
    return str(getattr(value, "value", value))


def is_access_denied(err):
    """
    :param err: exception raised by Azure SDK

    :return: boolean, if exception is caused by missing permissions
    """
    if getattr(err, "status_code", None) == 403:
        return True
    error = getattr(err, "error", None)
    return getattr(error, "code", None) in ACCESS_DENIED_CODES


class StorageOperations(object):
    @staticmethod
    def get_public_containers(containers):
        """
        :param containers: dict {container name: public access level}

        :return: dict with containers which allow anonymous access {container name: public access level}
        """
        return {name: level for name, level in containers.items() if level in PUBLIC_ACCESS_LEVELS}

    @staticmethod
    def blob_public_access_allowed(storage_account):
        """
        :param storage_account: `StorageAccount` as Azure SDK returns

        :return: boolean, if storage account allows public access to blob containers.
                 Not set `allow_blob_public_access` means allowed (default for accounts created with old API versions).
        """
        return getattr(storage_account, "allow_blob_public_access", None) is not False


class AzureStorageAccount(object):
    """
    Basic class for Azure storage account.
    Encapsulates name/resource group/location/tags and dict with containers public access levels.
    """
    def __init__(self, account, resource_id, name, location, tags, allow_blob_public_access, containers=None):
        """
        :param account: `AzureAccount` instance where storage account is present

        :param resource_id: storage account resource id
        :param name: storage account name
        :param location: storage account location (f.e. `westeurope`)
        :param tags: dict with storage account tags
        :param allow_blob_public_access: boolean, if public access to blob containers is allowed on account level
        :param containers: dict {container name: public access level}
        """
        self.account = account
        self.id = resource_id
        self.name = name
        self.resource_group = parse_resource_id(resource_id)["resource_group"]
        self.location = location
        self.tags = dict(tags or {})
        self.allow_blob_public_access = allow_blob_public_access
        self.containers = containers or {}
        self.backup_filename = pathlib.Path(f"{self.name}.json")

    def __str__(self):
        return f"{self.__class__.__name__}(Name={self.name}, ResourceGroup={self.resource_group}, Public={self.public})"

    @property
    def public_containers(self):
        """ :return: dict with containers which allow anonymous access {container name: public access level} """
        if not self.allow_blob_public_access:
            return {}
        return StorageOperations.get_public_containers(self.containers)

    @property
    def public(self):
        """
        :return: boolean, True - if storage account allows public blob access and has public containers
                          False - otherwise
        """
        return bool(self.public_containers)

    @property
    def backup(self):
        """ :return: dict with storage account public access state to save before remediation """
        return {
            "id": self.id,
            "name": self.name,
            "resource_group": self.resource_group,
            "allow_blob_public_access": self.allow_blob_public_access,
            "containers": self.containers,
        }

    def backup_s3(self, s3_client, bucket):
        """
        Backup storage account public access state (account level flag and containers access levels) json to S3.

        :param s3_client: S3 boto3 client
        :param bucket: S3 bucket name where to put backup

        :return: S3 path (without bucket name) to saved object with backup
        """
        timestamp = datetime.now(timezone.utc).isoformat('T', 'seconds')
        path = (f"azure_storage_public_access/"
                f"{self.account.id}/"
                f"{self.backup_filename.stem}_{timestamp}"
                f"{self.backup_filename.suffix}")
        if S3Operations.object_exists(s3_client, bucket, path):
            raise Exception(f"s3://{bucket}/{path} already exists")
        S3Operations.put_object(s3_client, bucket, path, jsonDumps(self.backup))
        return path

    def restrict(self, client):
        """
        Set public access level `None` on all public containers and disallow public blob access on account level.

        :param client: `azure.mgmt.storage.StorageManagementClient` instance

        :return: boolean, True - if all changes were applied successfully
                          False - otherwise

        .. note:: This keeps `self.containers` unchanged.
                  You need to recheck storage account to ensure that it was really restricted.
        """
        from azure.mgmt.storage.models import BlobContainer, PublicAccess, StorageAccountUpdateParameters

        succeed = True
        for container in self.public_containers:
            try:
                client.blob_containers.update(self.resource_group, self.name, container,
                                              BlobContainer(public_access=PublicAccess.NONE))
            except Exception:
                logging.exception(f"Failed to restrict '{container}' container public access in {self}")
                succeed = False

        try:
            client.storage_accounts.update(self.resource_group, self.name,
                                           StorageAccountUpdateParameters(allow_blob_public_access=False))
        except Exception:
            logging.exception(f"Failed to disallow blob public access for {self}")
            succeed = False

        return succeed

    def contains_tags(self, tags):
        """
        :param tags: dict {tag name: [allowed values]}

        :return: boolean, if storage account has all tags with one of allowed values
        """
        for tag_name in tags:
            if tag_name not in self.tags:
                return False
            if self.tags[tag_name] not in tags[tag_name]:
                return False
        return True


class AzureStoragePublicAccessChecker(object):
    """
    Basic class for checking Azure storage accounts public blob access in subscription.
    Encapsulates discovered storage accounts.
    """
    def __init__(self, account):
        """
        :param account: `AzureAccount` instance with storage accounts to check
        """
        self.account = account
        self.storage_accounts = []
        self._client = None

    @property
    def client(self):
        """ :return: `azure.mgmt.storage.StorageManagementClient` for subscription """
        if self._client is None:
            from azure.mgmt.storage import StorageManagementClient
            self._client = self.account.client(StorageManagementClient)
        return self._client

    def get_storage_account(self, name):
        """
        :return: `AzureStorageAccount` by name
        """
        for storage_account in self.storage_accounts:
            if storage_account.name == name:
                return storage_account
        return None

    def get_containers(self, resource_group, name):
        """
        :return: dict {container name: public access level} or None if containers can't be listed
        """
        try:
            return {container.name: access_level(container.public_access)
                    for container in self.client.blob_containers.list(resource_group, name)}
        except Exception as err:
            if is_access_denied(err):
                logging.error(f"Access denied in {self.account} "
                              f"(Microsoft.Storage/storageAccounts/blobServices/containers/read, "
                              f"resource='{name}')")
            else:
                logging.exception(f"Failed to list '{name}' containers in {self.account}")
            return None

    def check(self, ids=None, tags=None):
        """
        Walk through storage accounts in the subscription and check them (public or not).
        Put all gathered storage accounts to `self.storage_accounts`.

        :param ids: list with storage account names to check, if it is not supplied - all accounts must be checked
        :param tags: dict with tags to filter storage accounts {tag name: [allowed values]}

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            storage_accounts = list(self.client.storage_accounts.list())
        except Exception as err:
            if is_access_denied(err):
                logging.error(f"Access denied in {self.account} "
                              f"(Microsoft.Storage/storageAccounts/read)")
            else:
                logging.exception(f"Failed to list storage accounts in {self.account}")
            return False

        for storage_account in storage_accounts:
            name = storage_account.name
            if ids is not None and name not in ids:
                continue

            resource_id = storage_account.id
            allowed = StorageOperations.blob_public_access_allowed(storage_account)
            containers = {}
            # containers can't be public if public blob access is disallowed on account level
            if allowed:
                containers = self.get_containers(parse_resource_id(resource_id)["resource_group"], name)
                if containers is None:
                    continue

            azure_storage_account = AzureStorageAccount(
                account=self.account,
                resource_id=resource_id,
                name=name,
                location=storage_account.location,
                tags=storage_account.tags,
                allow_blob_public_access=allowed,
                containers=containers,
            )
            if tags is not None and not azure_storage_account.contains_tags(tags):
                continue
            self.storage_accounts.append(azure_storage_account)
        return True
