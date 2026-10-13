import logging


from google.api_core import exceptions as gcp_exceptions
from google.cloud import compute_v1


def resource_short_name(url):
    """
    :param url: GCP resource url or partial path
                (f.e. `https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a`)

    :return: last path element of url (f.e. `us-central1-a`) or None for empty url
    """
    return url.rstrip("/").rsplit("/", 1)[-1] if url else None


class GCPDisk(object):
    """
    Basic class for GCP Compute Engine persistent disk.
    Encapsulates `name`/`zone`/`status`/`labels`/`users` and encryption details.
    """
    # encryption types
    GOOGLE_MANAGED = "google-managed"
    CUSTOMER_MANAGED = "customer-managed"
    CUSTOMER_SUPPLIED = "customer-supplied"

    def __init__(self, account, source):
        """
        :param account: `GCPAccount` instance where disk is present
        :param source: single `google.cloud.compute_v1.Disk` element as GCP returns
        """
        self.source = source
        self.account = account
        self.name = source.name
        self.zone = resource_short_name(source.zone)
        # regional (replicated) disks have `region` and `replica_zones` instead of `zone`
        self.region = resource_short_name(source.region)
        self.status = source.status
        self.size_gb = source.size_gb
        self.type = resource_short_name(source.type_)
        self.self_link = source.self_link
        self.users = [resource_short_name(user) for user in source.users]
        self.tags = dict(source.labels)
        encryption_key = source.disk_encryption_key
        self.kms_key_name = encryption_key.kms_key_name or None
        # GCP never returns raw CSEK key, only its `sha256` hash
        self.csek = bool(encryption_key.sha256 or encryption_key.raw_key or encryption_key.rsa_encrypted_key)

    @property
    def location(self):
        """ :return: disk zone (for zonal disks) or region (for regional disks) """
        return self.zone or self.region

    @property
    def id(self):
        """ :return: disk identifier unique in project - `{zone}/{disk name}` """
        return f"{self.location}/{self.name}"

    @property
    def encryption(self):
        """ :return: disk encryption type (one of `GOOGLE_MANAGED`, `CUSTOMER_MANAGED`, `CUSTOMER_SUPPLIED`) """
        if self.kms_key_name:
            return self.CUSTOMER_MANAGED
        if self.csek:
            return self.CUSTOMER_SUPPLIED
        return self.GOOGLE_MANAGED

    @property
    def encrypted(self):
        """
        :return: boolean, True - if disk is encrypted with customer-managed (CMEK) or customer-supplied (CSEK) key
                          False - if disk uses Google-managed encryption only
        """
        return self.encryption != self.GOOGLE_MANAGED

    def __str__(self):
        return (f"{self.__class__.__name__}(Id={self.id}, Encryption={self.encryption}, "
                f"Status={self.status}, Users={len(self.users)})")


class GCPUnencryptedDisksChecker(object):
    """
    Basic class for checking GCP persistent disks encryption in project.
    Encapsulates discovered disks.
    """
    def __init__(self, account):
        """
        :param account: `GCPAccount` instance with disks to check
        """
        self.account = account
        self.disks = []

    def get_disk(self, id):
        """
        :return: `GCPDisk` by id (`{zone}/{disk name}`)
        """
        for disk in self.disks:
            if disk.id == id:
                return disk
        return None

    @staticmethod
    def match_tags(disk, tags):
        """
        :param disk: `GCPDisk` instance
        :param tags: dict with labels to match {key: value or list of values}

        :return: boolean, if disk labels match all given tags
        """
        for key, value in (tags or {}).items():
            values = value if isinstance(value, list) else [value]
            if disk.tags.get(key) not in values:
                return False
        return True

    def check(self, ids=None, tags=None):
        """
        Walk through persistent disks in all project zones/regions and put them to `self.disks`.

        :param ids: list with disk ids (`{zone}/{disk name}`) to check,
                    if it is not supplied - only disks with Google-managed encryption are collected
        :param tags: dict with disk labels to filter by

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            client = self.account.client(compute_v1.DisksClient)
            scoped_lists = client.aggregated_list(request={
                "project": self.account.id,
                "return_partial_success": True,
            })
            disks = []
            for _scope, scoped_list in scoped_lists:
                for source in scoped_list.disks:
                    disks.append(GCPDisk(self.account, source))
        except (gcp_exceptions.Forbidden, gcp_exceptions.Unauthorized) as err:
            logging.error(f"Access denied in {self.account} (compute.disks.list): {err}")
            return False
        except Exception:
            logging.exception(f"Failed to list disks in {self.account}")
            return False

        for disk in disks:
            if ids:
                # if ids is set - check given ids regardless of encryption status
                if disk.id not in ids:
                    continue
            elif disk.encrypted:
                # else get only unencrypted disks
                continue
            if not self.match_tags(disk, tags):
                continue
            self.disks.append(disk)
        return True
