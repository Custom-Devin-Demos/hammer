import json
import logging
import ipaddress

from datetime import datetime, timezone
from library.utility import jsonDumps
from library.aws.s3 import S3Operations


# protocols for which GCP firewall `allowed` entry may limit ports (names and IANA numbers)
PORT_PROTOCOLS = ["tcp", "udp", "sctp", "6", "17", "132"]
# protocol which allows traffic on all protocols and ports
ALL_PROTOCOLS = "all"


def compute_v1():
    """ :return: lazily imported `google.cloud.compute_v1` module """
    from google.cloud import compute_v1 as module
    return module


def short_name(url):
    """ :return: last part of GCP resource url (f.e. network name from network self link) """
    return url.rstrip("/").split("/")[-1] if url else url


def is_open_range(cidr):
    """
    :param cidr: string with IPv4 or IPv6 address/subnet

    :return: boolean, True - if cidr is world-wide open (`0.0.0.0/0`, `::/0`)
    """
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen == 0
    except ValueError:
        logging.warning(f"Failed to parse source range '{cidr}'")
        return False


def source_as_dict(source):
    """
    :param source: `compute_v1.Firewall` instance (or dict)

    :return: dict with firewall rule properties (ready to be dumped to json)
    """
    if isinstance(source, dict):
        return source
    to_dict = getattr(type(source), "to_dict", None)
    if to_dict is not None:
        return to_dict(source)
    return dict(vars(source))


class FirewallOperations:
    @staticmethod
    def backup_s3(account,
                  s3_client, bucket,
                  source):
        """
        Backup given firewall rule json to S3

        :param account: `GCPAccount` instance
        :param s3_client: S3 boto3 client
        :param bucket: bucket name for backup
        :param source: dict with firewall rule properties

        :return: S3 path (without bucket name) to saved object with firewall rule backup
        """
        rule_name = source["name"]
        timestamp = datetime.now(timezone.utc).isoformat('T', 'seconds')
        # this prefix MUST match prefix in find_source_s3
        prefix = f"gcp_firewall/{account.id}/"
        path = (f"{prefix}"
                f"{rule_name}_{timestamp}.json")
        if S3Operations.object_exists(s3_client, bucket, path):
            raise Exception(f"s3://{bucket}/{path} already exists")
        S3Operations.put_object(s3_client, bucket, path, source)
        return path

    @staticmethod
    def find_source_s3(account,
                       s3_client, bucket,
                       rule_name):
        """
        Find the most recent backup for firewall rule on S3

        :param account: `GCPAccount` instance
        :param s3_client: S3 boto3 client
        :param bucket: bucket name for backup
        :param rule_name: firewall rule name to search for

        :return: dict with firewall rule properties (as saved by `backup_s3`)
        """
        # this prefix MUST match prefix in backup_s3
        prefix = f"gcp_firewall/{account.id}/"
        objects = s3_client.list_objects(
            Bucket=bucket,
            Prefix=prefix
        ).get('Contents')
        if objects is None:
            logging.error(f"Failed to find '{rule_name}' firewall rule backup in {account}")
            return None
        backup_objects = [obj["Key"] for obj in objects if obj.get("Key", "").startswith(f"{prefix}{rule_name}_")]
        if not backup_objects:
            logging.error(f"Failed to find '{rule_name}' firewall rule backup in {account}")
            return None
        # return most recent backup
        recent_backup = max(backup_objects)
        source = json.loads(S3Operations.get_object(s3_client, bucket, recent_backup))
        assert rule_name == source["name"]
        return source

    @staticmethod
    def patch(firewalls_client, project, rule_name, **fields):
        """
        Patch firewall rule and wait for operation to complete

        :param firewalls_client: `compute_v1.FirewallsClient` instance
        :param project: GCP project id
        :param rule_name: firewall rule name
        :param fields: `compute_v1.Firewall` fields to patch (f.e. `source_ranges`, `disabled`)

        :return: operation result
        """
        firewall_resource = compute_v1().Firewall(**fields)
        operation = firewalls_client.patch(
            project=project,
            firewall=rule_name,
            firewall_resource=firewall_resource,
        )
        return operation.result()

    @classmethod
    def restrict(cls, firewalls_client, project, rule_name, source_ranges, open_ranges):
        """
        Remove world-wide open ranges from firewall rule source ranges.
        If no source ranges remain - disable firewall rule
        (patch can't clear repeated field and ingress rule without sources is open to the world).

        :param firewalls_client: `compute_v1.FirewallsClient` instance
        :param project: GCP project id
        :param rule_name: firewall rule name
        :param source_ranges: list with current firewall rule source ranges
        :param open_ranges: list with source ranges to remove

        :return: list with remaining source ranges (empty list if rule was disabled)
        """
        remaining = [cidr for cidr in source_ranges if cidr not in open_ranges]
        if remaining:
            logging.debug(f"Restricting '{rule_name}' source ranges to {remaining} in '{project}'")
            cls.patch(firewalls_client, project, rule_name, source_ranges=remaining)
        else:
            logging.debug(f"Disabling '{rule_name}' firewall rule in '{project}' (no restricted source ranges left)")
            cls.patch(firewalls_client, project, rule_name, disabled=True)
        return remaining

    @classmethod
    def restore_s3(cls,
                   account,
                   s3_client, bucket,
                   rule_name):
        """
        Restore firewall rule source ranges and disabled state from the most recent S3 backup

        :param account: `GCPAccount` instance
        :param s3_client: S3 boto3 client
        :param bucket: bucket name with backup
        :param rule_name: firewall rule name to restore

        :return: nothing
        """
        source = cls.find_source_s3(account, s3_client, bucket, rule_name)
        if source is None:
            return
        firewalls_client = account.client(compute_v1().FirewallsClient)
        cls.patch(firewalls_client, account.id, rule_name,
                  source_ranges=source.get("source_ranges", []),
                  disabled=source.get("disabled", False))


class FirewallPermission(object):
    """
    Basic class for firewall rule `allowed` entry.
    Encapsulates protocol and list of port ranges.
    """
    def __init__(self, allowed):
        """
        :param allowed: single `compute_v1.Allowed` element as GCP returns
        """
        self.protocol = str(allowed.I_p_protocol).lower()
        self.ports = [str(port) for port in (allowed.ports or [])]

    def __str__(self):
        return f"{self.protocol}:{self.ports_str}"

    @property
    def ports_str(self):
        """ :return: human readable ports ("22", "22,8000-8080", "all") """
        return ",".join(self.ports) if self.ports and self.protocol != ALL_PROTOCOLS else "all"

    @property
    def port_ranges(self):
        """
        :return: list with tuples (from_port, to_port) or None if entry allows all ports
        """
        if self.protocol == ALL_PROTOCOLS or not self.ports:
            return None
        ranges = []
        for port in self.ports:
            if "-" in port:
                from_port, to_port = port.split("-", 1)
            else:
                from_port = to_port = port
            ranges.append((int(from_port), int(to_port)))
        return ranges

    def unrestricted(self, restricted_ports):
        """
        :param restricted_ports: list with ports which must not be open to the world

        :return: boolean, True - if entry allows access to any of `restricted_ports`
        """
        if self.protocol != ALL_PROTOCOLS and self.protocol not in PORT_PROTOCOLS:
            logging.debug(f"Skipping '{self.protocol}' protocol (has no ports)")
            return False
        port_ranges = self.port_ranges
        if port_ranges is None:
            logging.debug(f"Marking all '{self.protocol}' ports as world-wide open")
            return True
        for from_port, to_port in port_ranges:
            if set(restricted_ports) & set(range(from_port, to_port + 1)):
                logging.debug(f"Marking world-wide open '{from_port}-{to_port}' in {restricted_ports}")
                return True
        logging.debug(f"Skipping '{self}' not in {restricted_ports}")
        return False


class FirewallRule(object):
    """
    Basic class for GCP VPC firewall rule.
    Encapsulates name/network/source ranges/targets and list of `allowed` entries.
    """
    def __init__(self, account, source):
        """
        :param account: `GCPAccount` instance where firewall rule is present
        :param source: single `compute_v1.Firewall` element as GCP returns
        """
        self.account = account
        self.source = source
        self.name = source.name
        self.id = str(source.id) if getattr(source, "id", None) else None
        self.self_link = getattr(source, "self_link", None)
        self.network_url = source.network
        self.network = short_name(source.network)
        self.direction = source.direction
        self.disabled = bool(source.disabled)
        self.priority = source.priority
        self.source_ranges = list(source.source_ranges or [])
        self.source_tags = list(getattr(source, "source_tags", None) or [])
        self.target_tags = list(source.target_tags or [])
        self.target_service_accounts = list(getattr(source, "target_service_accounts", None) or [])
        self.permissions = [FirewallPermission(allowed) for allowed in (source.allowed or [])]
        # list with world-wide open source ranges which give access to restricted ports (filled by `check`)
        self.open_ranges = []
        # list with `FirewallPermission` elements which give access to restricted ports (filled by `check`)
        self.open_permissions = []
        # GCP firewall rules do not support labels
        self.tags = {}

    def __str__(self):
        perms = ", ".join([str(perm) for perm in self.permissions])
        return (f"{self.__class__.__name__}(Name={self.name}, Network={self.network}, "
                f"SourceRanges={self.source_ranges}, Allowed=[{perms}])")

    def check(self, restricted_ports):
        """
        Mark world-wide open source ranges and `allowed` entries giving access to `restricted_ports`.

        :param restricted_ports: list with ports to consider firewall rule as not restricted

        :return: nothing
        """
        self.open_ranges = []
        self.open_permissions = []
        logging.debug(f"Checking {self}")
        if self.direction != "INGRESS":
            logging.debug(f"Skipping '{self.direction}' firewall rule '{self.name}'")
            return
        if self.disabled:
            logging.debug(f"Skipping disabled firewall rule '{self.name}'")
            return
        open_ranges = [cidr for cidr in self.source_ranges if is_open_range(cidr)]
        if not open_ranges:
            logging.debug(f"Skipping restricted firewall rule '{self.name}'")
            return
        open_permissions = [perm for perm in self.permissions if perm.unrestricted(restricted_ports)]
        if open_permissions:
            self.open_ranges = open_ranges
            self.open_permissions = open_permissions

    @property
    def restricted(self):
        """
        :return: boolean, True - if firewall rule does not give world-wide access to restricted ports
                          False - otherwise
        """
        return not self.open_permissions

    @property
    def rules(self):
        """
        :return: list with dicts describing world-wide open access (protocol, ports, source, priority)
        """
        return [
            {
                "protocol": perm.protocol,
                "ports": perm.ports_str,
                "source": cidr,
                "priority": self.priority,
            }
            for perm in self.open_permissions
            for cidr in self.open_ranges
        ]

    def backup_s3(self, s3_client, bucket):
        """
        Backup firewall rule source (as GCP returns) to S3

        :param s3_client: S3 boto3 client
        :param bucket: bucket name for backup

        :return: S3 path (without bucket name) to saved object with firewall rule backup
        """
        return FirewallOperations.backup_s3(
            self.account,
            s3_client, bucket,
            json.loads(jsonDumps(source_as_dict(self.source))))

    def restrict(self):
        """
        Remove world-wide open source ranges from firewall rule (disable rule if nothing remains)

        :return: None (in case of any error)
                 number of removed source ranges (0 if rule is already restricted)

        .. note:: It does not change `open_ranges`/`open_permissions`.
                  You need to recheck firewall rule to ensure that it was really restricted.
        """
        if self.restricted:
            return 0
        try:
            FirewallOperations.restrict(
                self.account.client(compute_v1().FirewallsClient),
                self.account.id,
                self.name,
                self.source_ranges,
                self.open_ranges)
        except Exception:
            logging.exception(f"Failed to restrict {self} in {self.account}")
            return None
        return len(self.open_ranges)


class FirewallChecker(object):
    """
    Basic class for checking GCP VPC firewall rules in project.
    Encapsulates check settings and discovered firewall rules.
    """
    def __init__(self,
                 account,
                 restricted_ports):
        """
        :param account: `GCPAccount` instance with firewall rules to check
        :param restricted_ports: list with ports to consider firewall rule as not restricted
        """
        self.account = account
        self.restricted_ports = restricted_ports
        self.rules = []

    def get_rule(self, name):
        """
        :return: `FirewallRule` by name
        """
        for rule in self.rules:
            if rule.name == name:
                return rule
        return None

    def check(self, ids=None, tags=None):
        """
        Walk through firewall rules in the project and check them (restricted or not).
        Put all gathered rules to `self.rules`.

        :param ids: list with firewall rule names to check, if it is not supplied - all rules must be checked
        :param tags: dict with network tags to filter rules by `target_tags` (values of dict are used,
                     GCP firewall rules do not support labels)

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            client = self.account.client(compute_v1().FirewallsClient)
            firewalls = list(client.list(project=self.account.id))
        except Exception as err:
            if type(err).__name__ in ["Forbidden", "PermissionDenied"]:
                logging.error(f"Access denied in {self.account} (compute.firewalls.list)")
            else:
                logging.exception(f"Failed to list firewall rules in {self.account}")
            return False

        network_tags = None
        if tags:
            network_tags = set()
            for value in tags.values():
                network_tags.update(value if isinstance(value, list) else [value])

        for firewall in firewalls:
            if ids and firewall.name not in ids:
                continue
            rule = FirewallRule(self.account, firewall)
            if network_tags is not None and not network_tags & set(rule.target_tags):
                continue
            rule.check(self.restricted_ports)
            self.rules.append(rule)
        return True
