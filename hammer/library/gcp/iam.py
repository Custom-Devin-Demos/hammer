"""
GCP service account keys checks and operations.

Google SDK (`google-cloud-iam`) is imported lazily, so module can be imported without SDK installed.
"""
import logging


from datetime import timezone


USER_MANAGED = "USER_MANAGED"
ACCESS_DENIED_ERRORS = ("PermissionDenied", "Forbidden", "Unauthenticated")


def is_access_denied(err):
    """ :return: boolean, if exception is GCP access denied error """
    return type(err).__name__ in ACCESS_DENIED_ERRORS


def as_utc_datetime(value):
    """
    Convert GCP timestamp to tz aware datetime.

    :param value: `datetime` (proto-plus returns `DatetimeWithNanoseconds`) or protobuf `Timestamp`

    :return: tz aware `datetime` or None if value is not set
    """
    if value is None:
        return None
    if hasattr(value, "ToDatetime"):
        if not value.seconds and not value.nanos:
            return None
        value = value.ToDatetime()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def enum_name(value):
    """ :return: name of proto enum value (f.e. 'USER_MANAGED') """
    return getattr(value, "name", value)


class GCPIAMOperations(object):
    @staticmethod
    def iam_client(account):
        """
        :param account: `GCPAccount` instance

        :return: `google.cloud.iam_admin_v1.IAMClient` with project credentials
        """
        from google.cloud import iam_admin_v1
        return account.client(iam_admin_v1.IAMClient)

    @staticmethod
    def list_service_accounts(iam_client, project_id):
        """
        :param iam_client: `IAMClient` instance
        :param project_id: GCP project id

        :return: list with `ServiceAccount` objects in project
        """
        return list(iam_client.list_service_accounts(request={"name": f"projects/{project_id}"}))

    @staticmethod
    def list_user_managed_keys(iam_client, service_account_name):
        """
        :param iam_client: `IAMClient` instance
        :param service_account_name: service account resource name (`projects/{project}/serviceAccounts/{email}`)

        :return: list with user managed `ServiceAccountKey` objects
        """
        response = iam_client.list_service_account_keys(request={
            "name": service_account_name,
            "key_types": [USER_MANAGED],
        })
        return [key for key in response.keys if enum_name(key.key_type) in (USER_MANAGED, 1)]

    @staticmethod
    def get_service_account_key(iam_client, key_name):
        """
        :param iam_client: `IAMClient` instance
        :param key_name: key resource name (`projects/{project}/serviceAccounts/{email}/keys/{key id}`)

        :return: `ServiceAccountKey` or None if key does not exist
        """
        try:
            return iam_client.get_service_account_key(request={"name": key_name})
        except Exception as err:
            if type(err).__name__ == "NotFound":
                return None
            raise

    @staticmethod
    def disable_service_account_key(iam_client, key_name):
        """
        Disable service account key (key can be enabled back with `enable_service_account_key`).

        :param iam_client: `IAMClient` instance
        :param key_name: key resource name (`projects/{project}/serviceAccounts/{email}/keys/{key id}`)

        :return: nothing
        """
        iam_client.disable_service_account_key(request={"name": key_name})


class GCPServiceAccount(object):
    """
    Basic class for GCP service account.
    Encapsulates email/name and user managed keys.
    """
    def __init__(self, checker, metadata):
        """
        :param checker: `GCPServiceAccountKeyChecker` instance
        :param metadata: `ServiceAccount` object as GCP returns
        """
        self.checker = checker
        self.name = metadata.name
        self.email = metadata.email
        self.unique_id = getattr(metadata, "unique_id", None)
        self.display_name = getattr(metadata, "display_name", None) or ""
        self.disabled = bool(getattr(metadata, "disabled", False))
        self.keys = []

    def __str__(self):
        return f"{self.__class__.__name__}(Email={self.email}, Keys={len(self.keys)})"

    def add_key(self, metadata):
        """
        Create and add new key to list of keys

        :param metadata: `ServiceAccountKey` object as GCP returns

        :return: created and added `GCPServiceAccountKey` instance
        """
        key = GCPServiceAccountKey(self, metadata)
        self.keys.append(key)
        return key

    @property
    def stale_keys(self):
        """ :return: list of stale `GCPServiceAccountKey` instances """
        return [key for key in self.keys if key.stale]


class GCPServiceAccountKey(object):
    """
    Basic class for GCP user managed service account key.
    Encapsulates key resource name, creation/expiration time and state.
    """
    def __init__(self, service_account, metadata):
        """
        :param service_account: `GCPServiceAccount` instance key belongs to
        :param metadata: `ServiceAccountKey` object as GCP returns
        """
        self.service_account = service_account
        # projects/{project}/serviceAccounts/{email}/keys/{key id}
        self.name = metadata.name
        self.id = self.name.rsplit("/", 1)[-1]
        self.created = as_utc_datetime(getattr(metadata, "valid_after_time", None))
        self.expires = as_utc_datetime(getattr(metadata, "valid_before_time", None))
        self.disabled = bool(getattr(metadata, "disabled", False))
        self.key_type = enum_name(getattr(metadata, "key_type", None))

    def __str__(self):
        return (f"{self.__class__.__name__}("
                f"Id={self.id}, "
                f"ServiceAccount={self.service_account.email}, "
                f"Created={self.created}, "
                f"Disabled={self.disabled}"
                f")")

    @property
    def age_days(self):
        """ :return: int, key age in days or None if creation time is unknown """
        if self.created is None or self.service_account.checker.now is None:
            return None
        return (self.service_account.checker.now - self.created).days

    @property
    def stale(self):
        """
        :return: boolean, True - if key is enabled and was created earlier than rotation criteria
                          False - otherwise
        """
        if self.disabled:
            return False
        checker = self.service_account.checker
        assert checker.now is not None
        assert checker.rotation_criteria_days is not None
        if self.created is None:
            logging.warning(f"Unknown creation time of '{self.name}' key, skipping")
            return False
        return (checker.now - self.created) > checker.rotation_criteria_days

    def disable(self):
        """ Disable current service account key """
        GCPIAMOperations.disable_service_account_key(self.service_account.checker.iam_client, self.name)


class GCPServiceAccountKeyChecker(object):
    """
    Basic class for checking GCP user managed service account keys in project.
    Encapsulates check settings and discovered keys grouped by service accounts.
    """
    def __init__(self, account, now=None, rotation_criteria_days=None):
        """
        :param account: `GCPAccount` instance with service accounts to check
        :param now: `datetime` object of current timestamp to compare key creation time with
        :param rotation_criteria_days: `timedelta` object to compare and mark keys as stale (created long time ago)
        """
        self.account = account
        self.now = now
        self.rotation_criteria_days = rotation_criteria_days
        self.service_accounts = []
        self._iam_client = None

    @property
    def iam_client(self):
        """ :return: cached `IAMClient` for project """
        if self._iam_client is None:
            self._iam_client = GCPIAMOperations.iam_client(self.account)
        return self._iam_client

    @property
    def keys(self):
        """ :return: list with all discovered `GCPServiceAccountKey` instances """
        return [key for service_account in self.service_accounts for key in service_account.keys]

    @property
    def stale_keys(self):
        """ :return: list with stale `GCPServiceAccountKey` instances """
        return [key for key in self.keys if key.stale]

    def get_key(self, name):
        """ :return: `GCPServiceAccountKey` by key resource name or id """
        for key in self.keys:
            if name in (key.name, key.id):
                return key
        return None

    def check(self, ids=None, tags=None):
        """
        Walk through service accounts in project and collect their user managed keys.
        Put all gathered service accounts to `self.service_accounts`.

        :param ids: list with service account emails or key resource names to check,
                    if it is not supplied - all keys must be checked
        :param tags: not used, GCP service accounts do not support labels (kept for interface compatibility)

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            service_accounts = GCPIAMOperations.list_service_accounts(self.iam_client, self.account.id)
        except Exception as err:
            if is_access_denied(err):
                logging.error(f"Access denied in {self.account} (iam.serviceAccounts.list)")
            else:
                logging.exception(f"Failed to list service accounts in {self.account}")
            return False

        for metadata in service_accounts:
            service_account = GCPServiceAccount(self, metadata)
            try:
                keys = GCPIAMOperations.list_user_managed_keys(self.iam_client, service_account.name)
            except Exception as err:
                if is_access_denied(err):
                    logging.error(f"Access denied in {self.account} (iam.serviceAccountKeys.list)")
                else:
                    logging.exception(f"Failed to list keys for {service_account.email} in {self.account}")
                return False

            for key_metadata in keys:
                if ids is not None and \
                   service_account.email not in ids and \
                   key_metadata.name not in ids:
                    continue
                key = service_account.add_key(key_metadata)
                logging.debug(f"Discovered {key}")
            self.service_accounts.append(service_account)
        return True
