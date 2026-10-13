import logging


from enum import Enum
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.mgmt.compute import ComputeManagementClient
from library.azure.utility import parse_resource_id


# `Encryption.type` values with customer-managed key (Disk Encryption Set) encryption at rest
CUSTOMER_KEY_ENCRYPTION_TYPES = [
    "EncryptionAtRestWithCustomerKey",
    "EncryptionAtRestWithPlatformAndCustomerKeys",
]
# `DiskSecurityProfile.security_type` values for confidential VM disks encrypted with customer-managed key
CUSTOMER_KEY_SECURITY_TYPES = [
    "ConfidentialVM_DiskEncryptedWithCustomerKey",
]


def enum_value(value):
    """ :return: plain value of Azure SDK enum (SDK enums are `str` subclasses), value as is otherwise """
    return value.value if isinstance(value, Enum) else value


def disk_property(disk, name):
    """
    Get managed disk property regardless of Azure SDK model layout
    (flattened in older `azure-mgmt-compute`, nested under `properties` in newer).

    :param disk: `azure.mgmt.compute.models.Disk` instance
    :param name: property name (f.e. `encryption`)

    :return: property value or None
    """
    value = getattr(disk, name, None)
    if value is None:
        properties = getattr(disk, "properties", None)
        if properties is not None:
            value = getattr(properties, name, None)
    return value


class AzureDisk(object):
    """
    Basic class for Azure managed disk.
    Encapsulates `id`/`name`/`location`/`resource_group`/`tags`, disk state and encryption details.
    """
    def __init__(self, account, source):
        """
        :param account: `AzureAccount` instance where managed disk is present
        :param source: `azure.mgmt.compute.models.Disk` instance as Azure SDK returns
        """
        self.source = source
        self.account = account
        self.id = source.id.lower()
        self.name = source.name
        self.location = source.location
        self.resource_group = parse_resource_id(source.id)["resource_group"]
        self.tags = dict(source.tags or {})
        self.managed_by = source.managed_by
        sku = getattr(source, "sku", None)
        self.sku = enum_value(getattr(sku, "name", None)) if sku is not None else None
        self.state = enum_value(disk_property(source, "disk_state"))
        self.size_gb = disk_property(source, "disk_size_gb")
        self.os_type = enum_value(disk_property(source, "os_type"))

        encryption = disk_property(source, "encryption")
        self.encryption_type = enum_value(getattr(encryption, "type", None)) if encryption is not None else None
        self.disk_encryption_set_id = getattr(encryption, "disk_encryption_set_id", None) if encryption is not None else None

        security_profile = disk_property(source, "security_profile")
        self.security_type = enum_value(getattr(security_profile, "security_type", None)) \
            if security_profile is not None else None

        encryption_settings = disk_property(source, "encryption_settings_collection")
        self.ade_enabled = bool(getattr(encryption_settings, "enabled", False)) \
            if encryption_settings is not None else False

    @property
    def customer_managed_key(self):
        """ :return: boolean, True - if disk is encrypted at rest with customer-managed key """
        return (self.encryption_type in CUSTOMER_KEY_ENCRYPTION_TYPES or
                bool(self.disk_encryption_set_id) or
                self.security_type in CUSTOMER_KEY_SECURITY_TYPES)

    @property
    def encrypted(self):
        """
        Disk is treated as encrypted when it uses customer-managed key or Azure Disk Encryption (ADE).
        Platform-managed key encryption only is not enough.

        :return: boolean
        """
        return self.customer_managed_key or self.ade_enabled

    def compliant(self, require_customer_managed_key=False):
        """
        :param require_customer_managed_key: if True - only customer-managed key encryption is acceptable

        :return: boolean, True - if disk encryption satisfies requirements
        """
        if require_customer_managed_key:
            return self.customer_managed_key
        return self.encrypted

    def __str__(self):
        return (f"{self.__class__.__name__}(Name={self.name}, Location={self.location}, "
                f"EncryptionType={self.encryption_type}, ADE={self.ade_enabled}, State={self.state})")


class AzureUnencryptedDisksChecker(object):
    """
    Basic class for checking Azure managed disks in subscription.
    Encapsulates discovered managed disks.
    """
    def __init__(self, account, require_customer_managed_key=False):
        """
        :param account: `AzureAccount` instance with managed disks to check
        :param require_customer_managed_key: if True - only customer-managed key encryption is acceptable
        """
        self.account = account
        self.require_customer_managed_key = require_customer_managed_key
        self.disks = []

    def get_disk(self, id):
        """
        :return: `AzureDisk` by resource id (case insensitive)
        """
        for disk in self.disks:
            if disk.id == id.lower():
                return disk
        return None

    def is_compliant(self, disk):
        """ :return: boolean, True - if `AzureDisk` encryption satisfies checker requirements """
        return disk.compliant(self.require_customer_managed_key)

    @property
    def unencrypted_disks(self):
        """ :return: list with discovered `AzureDisk` instances not satisfying encryption requirements """
        return [disk for disk in self.disks if not self.is_compliant(disk)]

    @staticmethod
    def match_tags(disk, tags):
        """
        :param tags: dict with tags to filter by ({key: value or [values]})

        :return: boolean, True - if disk has all given tags with one of given values
        """
        for key, value in (tags or {}).items():
            values = value if isinstance(value, list) else [value]
            if disk.tags.get(key) not in values:
                return False
        return True

    def check(self, ids=None, tags=None):
        """
        Walk through managed disks in the subscription and put them to `self.disks`.

        :param ids: list with disk resource ids to check, if it is not supplied - all disks must be checked
        :param tags: dict with tags to filter disks by

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            client = self.account.client(ComputeManagementClient)
            if ids:
                sources = []
                for disk_id in ids:
                    parsed = parse_resource_id(disk_id)
                    try:
                        sources.append(client.disks.get(parsed["resource_group"], parsed["name"]))
                    except ResourceNotFoundError:
                        logging.debug(f"Disk '{disk_id}' not found in {self.account}")
            else:
                sources = list(client.disks.list())
        except HttpResponseError as err:
            if err.status_code in [401, 403]:
                logging.error(f"Access denied in {self.account} "
                              f"(Microsoft.Compute/disks/read): {err.message}")
            else:
                logging.exception(f"Failed to list managed disks in {self.account}")
            return False
        except Exception:
            logging.exception(f"Failed to list managed disks in {self.account}")
            return False

        for source in sources:
            disk = AzureDisk(self.account, source)
            if tags and not self.match_tags(disk, tags):
                continue
            self.disks.append(disk)
        return True
