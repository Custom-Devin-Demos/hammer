"""
Azure network security groups (NSG) checker and remediation operations.

Azure SDK management client is imported lazily, so this module can be imported without `azure-mgmt-network`.
"""
import logging


from datetime import datetime, timezone
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from library.utility import jsonDumps
from library.aws.s3 import S3Operations
from library.azure.utility import parse_resource_id


# NSG rule source address prefixes which mean "any address in the Internet"
OPEN_SOURCES = {"*", "any", "internet", "0.0.0.0/0", "::/0"}
# source to replace world-wide open source with if no other sources left in rule during remediation
RESTRICTED_SOURCE = "VirtualNetwork"
MAX_PORT = 65535


def _value(item):
    """ :return: string value of SDK enum (or string as is) """
    return getattr(item, "value", item)


def _lower(item):
    """ :return: lower-cased string value of SDK enum/string (or None) """
    value = _value(item)
    return value.lower() if isinstance(value, str) else value


def _to_dict(source):
    """ :return: json serializable representation of SDK model """
    if hasattr(source, "as_dict"):
        return source.as_dict()
    if isinstance(source, dict):
        return {key: _to_dict(value) for key, value in source.items()}
    if isinstance(source, (list, tuple)):
        return [_to_dict(item) for item in source]
    if hasattr(source, "__dict__"):
        return {key: _to_dict(value) for key, value in vars(source).items() if not key.startswith("_")}
    return _value(source)


def parse_port_range(port_range):
    """
    Parse NSG rule port range.

    :param port_range: string like "22", "1000-2000" or "*"

    :return: tuple (from_port, to_port) or None if port range can't be parsed
    """
    port_range = str(port_range).strip()
    if port_range == "*":
        return 0, MAX_PORT
    try:
        if "-" in port_range:
            from_port, to_port = port_range.split("-", 1)
            return int(from_port), int(to_port)
        return int(port_range), int(port_range)
    except ValueError:
        logging.warning(f"Failed to parse port range '{port_range}'")
        return None


class AzureNSGOperations(object):
    @staticmethod
    def backup_s3(account, s3_client, bucket, nsg_name, resource_group, source):
        """
        Backup given network security group json to S3

        :param account: `AzureAccount` instance
        :param s3_client: S3 boto3 client
        :param bucket: bucket name for backup
        :param nsg_name: network security group name
        :param resource_group: network security group resource group name
        :param source: network security group json (dict)

        :return: S3 path (without bucket name) to saved object with network security group backup
        """
        timestamp = datetime.now(timezone.utc).isoformat('T', 'seconds')
        path = (f"azure_nsg/{account.id}/{resource_group}/"
                f"{nsg_name}_{timestamp}.json")
        if S3Operations.object_exists(s3_client, bucket, path):
            raise Exception(f"s3://{bucket}/{path} already exists")
        S3Operations.put_object(s3_client, bucket, path, jsonDumps(source))
        return path

    @staticmethod
    def update_rule(network_client, resource_group, nsg_name, rule_name, rule):
        """
        Create or update security rule in network security group (waits for operation to finish)

        :param network_client: `azure.mgmt.network.NetworkManagementClient` instance
        :param resource_group: network security group resource group name
        :param nsg_name: network security group name
        :param rule_name: security rule name
        :param rule: `azure.mgmt.network.models.SecurityRule` instance

        :return: updated `SecurityRule`
        """
        return network_client.security_rules.begin_create_or_update(
            resource_group, nsg_name, rule_name, rule
        ).result()


class AzureNSGRule(object):
    """
    Basic class for NSG security rule.
    Encapsulates name/priority/protocol/sources/destination ports and restriction status.
    """
    def __init__(self, nsg, source):
        """
        :param nsg: `AzureNSG` instance which contains this rule
        :param source: `azure.mgmt.network.models.SecurityRule` instance as Azure returns
        """
        self.nsg = nsg
        self.source = source
        self.name = source.name
        self.priority = source.priority
        self.protocol = _value(source.protocol) or "*"
        self.direction = _value(source.direction)
        self.access = _value(source.access)
        self.sources = []
        if source.source_address_prefix:
            self.sources.append(source.source_address_prefix)
        self.sources += list(source.source_address_prefixes or [])
        self.ports = []
        if source.destination_port_range:
            self.ports.append(str(source.destination_port_range))
        self.ports += [str(port) for port in source.destination_port_ranges or []]
        # world-wide open sources (filled in `check`)
        self.open_sources = []

    def __str__(self):
        return (f"{self.__class__.__name__}(Name={self.name}, Priority={self.priority}, "
                f"Protocol={self.protocol}, Ports={self.ports}, Sources={self.sources})")

    @property
    def restricted(self):
        """ :return: boolean, True - if rule does not allow world-wide access to restricted ports """
        return len(self.open_sources) == 0

    def check(self, restricted_ports):
        """
        Check if rule allows inbound access to restricted ports from the Internet.
        Put world-wide open sources to `self.open_sources`.

        :param restricted_ports: list with ports to consider rule as not restricted

        :return: nothing
        """
        self.open_sources = []
        if _lower(self.direction) != "inbound" or _lower(self.access) != "allow":
            return
        if _lower(self.protocol) == "icmp":
            logging.debug(f"Skipping ICMP rule '{self.name}'")
            return
        open_sources = [source for source in self.sources if source.lower() in OPEN_SOURCES]
        if not open_sources:
            return
        ports = set()
        for port_range in self.ports or ["*"]:
            parsed = parse_port_range(port_range)
            if parsed is None:
                continue
            from_port, to_port = parsed
            ports.update(range(from_port, to_port + 1))
        if set(restricted_ports) & ports:
            logging.debug(f"Marking rule '{self.name}' world-wide open {self.ports} from {open_sources}")
            self.open_sources = open_sources

    def as_issue_rule(self):
        """ :return: dict with rule details to store in DDB issue """
        return {
            "name": self.name,
            "protocol": self.protocol,
            "ports": ",".join(self.ports) or "*",
            "source": ",".join(self.open_sources),
            "priority": self.priority,
        }

    def restrict(self, network_client):
        """
        Remove world-wide open sources from rule (replace with `VirtualNetwork` if no sources left).

        :param network_client: `NetworkManagementClient` instance

        :return: nothing, can raise exception
        """
        sources = [source for source in self.sources if source.lower() not in OPEN_SOURCES]
        if not sources:
            sources = [RESTRICTED_SOURCE]
        logging.debug(f"Restricting rule '{self.name}' in '{self.nsg.name}' sources {self.sources} -> {sources}")
        if len(sources) == 1:
            self.source.source_address_prefix = sources[0]
            self.source.source_address_prefixes = []
        else:
            self.source.source_address_prefix = None
            self.source.source_address_prefixes = sources
        AzureNSGOperations.update_rule(network_client,
                                       self.nsg.resource_group, self.nsg.name,
                                       self.name, self.source)


class AzureNSG(object):
    """
    Basic class for Azure network security group.
    Encapsulates id/name/location/resource group/tags, list of `AzureNSGRule` and attachments.
    """
    def __init__(self, account, source):
        """
        :param account: `AzureAccount` instance where NSG is present
        :param source: `azure.mgmt.network.models.NetworkSecurityGroup` instance as Azure returns
        """
        self.account = account
        self.source = source
        self.id = source.id.lower()
        self.name = source.name
        self.location = source.location
        self.resource_group = parse_resource_id(source.id)["resource_group"]
        self.tags = dict(source.tags or {})
        self.network_interfaces = sorted(nic.id for nic in source.network_interfaces or [] if nic.id)
        self.subnets = sorted(subnet.id for subnet in source.subnets or [] if subnet.id)
        self.rules = [AzureNSGRule(self, rule) for rule in source.security_rules or []]

    def __str__(self):
        rules = ", ".join([str(rule) for rule in self.rules])
        return f"{self.__class__.__name__}(Name={self.name}, Id={self.id}, Rules=[{rules}])"

    def check(self, restricted_ports):
        """
        Walk through all `AzureNSGRule` and mark not restricted rules.

        :param restricted_ports: list with ports to consider rule as not restricted

        :return: nothing
        """
        for rule in self.rules:
            rule.check(restricted_ports)

    @property
    def open_rules(self):
        """ :return: list with not restricted `AzureNSGRule` sorted by priority/name """
        return sorted([rule for rule in self.rules if not rule.restricted],
                      key=lambda rule: (rule.priority or 0, rule.name))

    @property
    def restricted(self):
        """ :return: boolean, True - if all NSG rules are restricted """
        return len(self.open_rules) == 0

    def backup_s3(self, s3_client, bucket):
        """
        Backup NSG source (as Azure returns) to S3

        :param s3_client: S3 boto3 client
        :param bucket: bucket name for backup

        :return: S3 path (without bucket name) to saved object with NSG backup
        """
        return AzureNSGOperations.backup_s3(self.account, s3_client, bucket,
                                            self.name, self.resource_group,
                                            _to_dict(self.source))

    def restrict(self, network_client):
        """
        Restrict all not restricted `AzureNSGRule` elements

        :param network_client: `NetworkManagementClient` instance

        :return: None (in case of any error)
                 number of processed rules

        .. note:: It does not reset `open_sources` for processed rules.
                  You need to recheck NSG to ensure that it was really restricted.
        """
        processed = 0
        for rule in self.open_rules:
            try:
                rule.restrict(network_client)
            except HttpResponseError as err:
                if err.status_code == 403:
                    logging.error(f"Access denied in {self.account} "
                                  f"(Microsoft.Network/networkSecurityGroups/securityRules/write)")
                else:
                    logging.exception(f"Failed to restrict {str(self)}")
                return None
            processed += 1
        return processed


class AzureNSGChecker(object):
    """
    Basic class for checking network security groups in Azure subscription.
    Encapsulates check settings and discovered NSGs.
    """
    def __init__(self, account, restricted_ports):
        """
        :param account: `AzureAccount` instance with NSGs to check
        :param restricted_ports: list with ports to consider NSG as not restricted
        """
        self.account = account
        self.restricted_ports = restricted_ports
        self.groups = []
        self._client = None

    @property
    def client(self):
        """ :return: `azure.mgmt.network.NetworkManagementClient` for current subscription """
        if self._client is None:
            from azure.mgmt.network import NetworkManagementClient
            self._client = self.account.client(NetworkManagementClient)
        return self._client

    def get_nsg(self, id):
        """
        :return: `AzureNSG` by resource id (case insensitive)
        """
        for group in self.groups:
            if group.id == id.lower():
                return group
        return None

    def _get_nsgs(self, ids):
        """ :return: list with NSGs by resource ids, skipping not existing NSGs """
        nsgs = []
        for nsg_id in ids:
            parsed = parse_resource_id(nsg_id)
            try:
                nsgs.append(self.client.network_security_groups.get(parsed["resource_group"], parsed["name"]))
            except ResourceNotFoundError:
                logging.debug(f"NSG '{nsg_id}' not found in {self.account}")
        return nsgs

    @staticmethod
    def tags_match(nsg_tags, tags):
        """ :return: boolean, if NSG tags match all given tags (tag value can be a list of acceptable values) """
        nsg_tags = nsg_tags or {}
        for key, value in tags.items():
            values = value if isinstance(value, list) else [value]
            if nsg_tags.get(key) not in values:
                return False
        return True

    def check(self, ids=None, tags=None):
        """
        Walk through NSGs in the subscription and check them (restricted or not).
        Put all gathered NSGs to `self.groups`.

        :param ids: list with NSG resource ids to check, if it is not supplied - all NSGs must be checked
        :param tags: dict with tags to filter NSGs by

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            if ids:
                nsgs = self._get_nsgs(ids)
            else:
                nsgs = list(self.client.network_security_groups.list_all())
        except HttpResponseError as err:
            if err.status_code == 403:
                logging.error(f"Access denied in {self.account} "
                              f"(Microsoft.Network/networkSecurityGroups/read)")
            else:
                logging.exception(f"Failed to list network security groups in {self.account}")
            return False
        except Exception:
            logging.exception(f"Failed to list network security groups in {self.account}")
            return False

        for source in nsgs:
            if tags and not self.tags_match(source.tags, tags):
                continue
            nsg = AzureNSG(self.account, source)
            nsg.check(self.restricted_ports)
            self.groups.append(nsg)
        return True
