"""
Azure storage account access keys rotation checking and remediation.

Storage account shared keys (`key1`/`key2`) grant full access to all data in a storage account,
so they must be rotated (regenerated) regularly, as IAM user access keys in AWS.
Key creation time is taken from storage account `keyCreationTime` property
(no `listKeys` permission is required for identification).
"""
import logging
import dateutil.parser


from datetime import datetime, timezone
from library.azure.utility import parse_resource_id


# names of storage account shared access keys
STORAGE_ACCOUNT_KEY_NAMES = ("key1", "key2")


def storage_client_class():
    """ :return: `azure.mgmt.storage.StorageManagementClient` class (imported lazily) """
    from azure.mgmt.storage import StorageManagementClient
    return StorageManagementClient


def is_access_denied(err):
    """ :return: boolean, if Azure SDK exception is caused by missing permissions """
    status_code = getattr(err, "status_code", None)
    error_code = getattr(getattr(err, "error", None), "code", None)
    return status_code in (401, 403) or error_code in ("AuthorizationFailed", "AuthenticationFailed")


def tags_match(resource_tags, tags):
    """
    :param resource_tags: dict with resource tags
    :param tags: dict with tags to match {key: value or [values]}

    :return: boolean, if resource has all tags from `tags` with one of required values
    """
    for key, value in tags.items():
        values = value if isinstance(value, list) else [value]
        if resource_tags.get(key, None) not in values:
            return False
    return True


class StorageKeyOperations(object):
    @staticmethod
    def regenerate_key(storage_client, resource_group, account_name, key_name):
        """
        Regenerate storage account access key.

        :param storage_client: `StorageManagementClient` instance
        :param resource_group: resource group name of storage account
        :param account_name: storage account name
        :param key_name: name of the key to regenerate (`key1`/`key2`)

        :return: nothing
        """
        from azure.mgmt.storage.models import StorageAccountRegenerateKeyParameters
        storage_client.storage_accounts.regenerate_key(
            resource_group,
            account_name,
            StorageAccountRegenerateKeyParameters(key_name=key_name)
        )


class StorageAccountKey(object):
    """
    Basic class for storage account access key.
    Encapsulates key name and creation time.
    """
    def __init__(self, storage_account, name, created):
        """
        :param storage_account: `StorageAccount` instance key belongs to
        :param name: key name (`key1`/`key2`)
        :param created: `datetime` (or ISO string) of key creation, None if unknown
        """
        self.storage_account = storage_account
        self.name = name
        if isinstance(created, str):
            created = dateutil.parser.parse(created)
        if isinstance(created, datetime) and created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        self.created = created

    def __str__(self):
        return f"{self.__class__.__name__}(Name={self.name}, Created={self.created_iso})"

    @property
    def created_iso(self):
        """ :return: ISO string with key creation time or None if unknown """
        return self.created.isoformat() if self.created is not None else None

    @property
    def stale(self):
        """
        :return: boolean, True - if shared key access is allowed and key was created earlier than
                                 rotation criteria (or creation time is unknown)
                          False - otherwise
        """
        if not self.storage_account.shared_key_access:
            return False
        if self.created is None:
            return True
        assert self.storage_account.now is not None
        assert self.storage_account.rotation_criteria_days is not None
        return (self.storage_account.now - self.created) > self.storage_account.rotation_criteria_days


class StorageAccount(object):
    """
    Basic class for Azure storage account.
    Encapsulates name/location/tags/resource group and access keys.
    """
    def __init__(self, account, source, now=None, rotation_criteria_days=None):
        """
        :param account: `AzureAccount` instance where storage account is present
        :param source: `azure.mgmt.storage.models.StorageAccount` as Azure SDK returns
        :param now: `datetime` object of current timestamp to compare key creation time with
        :param rotation_criteria_days: `timedelta` object to compare and mark key as stale
        """
        self.account = account
        self.now = now
        self.rotation_criteria_days = rotation_criteria_days
        self.id = source.id
        self.name = source.name
        self.location = getattr(source, "location", None)
        self.tags = dict(getattr(source, "tags", None) or {})
        self.resource_group = parse_resource_id(self.id)["resource_group"]
        # `allow_shared_key_access` is None when it was never set, which means shared key access is allowed
        allow_shared_key_access = getattr(source, "allow_shared_key_access", None)
        self.shared_key_access = allow_shared_key_access is None or bool(allow_shared_key_access)
        key_creation_time = getattr(source, "key_creation_time", None)
        self.keys = [
            StorageAccountKey(self, key_name, getattr(key_creation_time, key_name, None))
            for key_name in STORAGE_ACCOUNT_KEY_NAMES
        ]

    def __str__(self):
        return (f"{self.__class__.__name__}(Name={self.name}, "
                f"ResourceGroup={self.resource_group}, "
                f"SharedKeyAccess={self.shared_key_access}, "
                f"StaleKeys={[key.name for key in self.stale_keys]})")

    @property
    def stale_keys(self):
        """ :return: list of stale `StorageAccountKey` instances """
        return [key for key in self.keys if key.stale]

    def regenerate_key(self, key_name):
        """ Regenerate storage account access key with given name """
        StorageKeyOperations.regenerate_key(
            self.account.client(storage_client_class()),
            self.resource_group,
            self.name,
            key_name
        )


class StorageKeysChecker(object):
    """
    Basic class for checking Azure storage accounts access keys rotation in subscription.
    Encapsulates discovered storage accounts.
    """
    def __init__(self, account, now=None, rotation_criteria_days=None):
        """
        :param account: `AzureAccount` instance with storage accounts to check
        :param now: `datetime` object of current timestamp to compare key creation time with
        :param rotation_criteria_days: `timedelta` object to compare and mark keys as stale
        """
        self.account = account
        self.now = now
        self.rotation_criteria_days = rotation_criteria_days
        self.storage_accounts = []

    def get_storage_account(self, name):
        """ :return: `StorageAccount` by name """
        for storage_account in self.storage_accounts:
            if storage_account.name == name:
                return storage_account
        return None

    def check(self, ids=None, tags=None):
        """
        Walk through storage accounts in the subscription and put them to `self.storage_accounts`.

        :param ids: list with storage account names to check, if it is not supplied - all storage accounts must be checked
        :param tags: dict with tags to filter storage accounts by ({key: value or [values]})

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            client = self.account.client(storage_client_class())
            sources = list(client.storage_accounts.list())
        except Exception as err:
            if is_access_denied(err):
                logging.error(f"Access denied in {self.account} "
                              f"(Microsoft.Storage/storageAccounts/read)")
            else:
                logging.exception(f"Failed to list storage accounts in {self.account}")
            return False

        for source in sources:
            if ids is not None and source.name not in ids:
                continue
            storage_account = StorageAccount(self.account, source,
                                             now=self.now,
                                             rotation_criteria_days=self.rotation_criteria_days)
            if tags and not tags_match(storage_account.tags, tags):
                continue
            logging.debug(f"Evaluated {storage_account}")
            self.storage_accounts.append(storage_account)
        return True
