import os
import json
import importlib.util
import pytest


from types import SimpleNamespace
from unittest import mock
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from library.azure import network
from library.azure.network import AzureNSGChecker, parse_port_range
from library.azure.utility import AzureAccount
from library.ddb_issues import IssueStatus, AzureNSGIssue


SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"
RESTRICTED_PORTS = [21, 22, 23, 3389, 1433, 3306, 5432]
REPORTING_REMEDIATION = os.path.join(os.path.dirname(__file__), "..", "hammer", "reporting-remediation")


def nsg_id(name, rg="rg-1"):
    return (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{rg}"
            f"/providers/Microsoft.Network/networkSecurityGroups/{name}")


def make_rule(name, source="*", sources=None, port=None, ports=None,
              protocol="Tcp", direction="Inbound", access="Allow", priority=100):
    return SimpleNamespace(name=name, priority=priority, protocol=protocol,
                           direction=direction, access=access,
                           source_address_prefix=source, source_address_prefixes=sources or [],
                           destination_port_range=port, destination_port_ranges=ports or [])


def make_nsg(name, rules, tags=None, nics=None, subnets=None, rg="RG-1"):
    return SimpleNamespace(id=nsg_id(name, rg), name=name, location="westeurope",
                           tags=tags if tags is not None else {"owner": "alice"},
                           security_rules=rules,
                           network_interfaces=[SimpleNamespace(id=nic) for nic in nics or []],
                           subnets=[SimpleNamespace(id=subnet) for subnet in subnets or []])


def make_checker(nsgs, account=None):
    checker = AzureNSGChecker(account=account or AzureAccount(SUBSCRIPTION, "azure-prod"),
                              restricted_ports=RESTRICTED_PORTS)
    checker._client = mock.Mock(name="network_client")
    checker._client.network_security_groups.list_all.return_value = iter(nsgs)
    return checker


def load_script(path, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPORTING_REMEDIATION, path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("port_range, expected", [
    ("22", (22, 22)), ("1000-2000", (1000, 2000)), ("*", (0, 65535)), ("abc", None),
])
def test_parse_port_range(port_range, expected):
    assert parse_port_range(port_range) == expected


@pytest.mark.parametrize("rule, is_open", [
    (make_rule("any-ssh", source="*", port="22"), True),
    (make_rule("internet-range", source="Internet", port="20-25"), True),
    (make_rule("world-ipv4-all-ports", source="0.0.0.0/0", port="*"), True),
    (make_rule("world-ipv6-list", source=None, sources=["10.0.0.0/8", "::/0"], ports=["80", "3389"]), True),
    (make_rule("any-protocol", source="*", port="5432", protocol="*"), True),
    (make_rule("private-ssh", source="10.0.0.0/8", port="22"), False),
    (make_rule("vnet-ssh", source="VirtualNetwork", port="22"), False),
    (make_rule("world-https", source="*", port="443"), False),
    (make_rule("world-ranges-not-restricted", source="*", ports=["80", "443", "8000-8080"]), False),
    (make_rule("deny-ssh", source="*", port="22", access="Deny"), False),
    (make_rule("outbound-ssh", source="*", port="22", direction="Outbound"), False),
    (make_rule("icmp", source="*", port="*", protocol="Icmp"), False),
])
def test_rule_detection(rule, is_open):
    checker = make_checker([make_nsg("nsg-1", [rule])])
    assert checker.check()
    nsg = checker.groups[0]
    assert nsg.restricted is not is_open


def test_nsg_details():
    nic = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-1/providers/Microsoft.Network/networkInterfaces/nic-1"
    nsg_source = make_nsg("nsg-1", [
        make_rule("world-rdp", source="*", port="3389", priority=200),
        make_rule("world-ssh", source=None, sources=["Internet", "1.2.3.4/32"], ports=["22", "80"], priority=100),
        make_rule("private", source="10.0.0.0/8", port="22", priority=300),
    ], nics=[nic], tags={"owner": "bob", "bu": "news"})
    checker = make_checker([nsg_source, make_nsg("nsg-2", [])])
    assert checker.check()
    assert len(checker.groups) == 2
    nsg = checker.get_nsg(nsg_id("NSG-1", "rg-1"))
    assert nsg.id == nsg_source.id.lower()
    assert nsg.resource_group == "RG-1"
    assert nsg.location == "westeurope"
    assert nsg.tags == {"owner": "bob", "bu": "news"}
    assert nsg.network_interfaces == [nic]
    assert nsg.subnets == []
    assert [rule.as_issue_rule() for rule in nsg.open_rules] == [
        {"name": "world-ssh", "protocol": "Tcp", "ports": "22,80", "source": "Internet", "priority": 100},
        {"name": "world-rdp", "protocol": "Tcp", "ports": "3389", "source": "*", "priority": 200},
    ]
    assert checker.get_nsg(nsg_id("nsg-2")).restricted


def test_check_with_real_sdk_models():
    models = pytest.importorskip("azure.mgmt.network.models")
    rule = models.SecurityRule(name="world-ssh", protocol="Tcp", source_address_prefix="*",
                               destination_port_range="22", access="Allow", direction="Inbound", priority=100)
    source = models.NetworkSecurityGroup(location="westeurope", security_rules=[rule], tags={"a": "b"})
    source.id = nsg_id("nsg-1")
    source.name = "nsg-1"
    checker = make_checker([source])
    assert checker.check()
    assert checker.groups[0].open_rules[0].as_issue_rule()["protocol"] == "Tcp"


def test_check_by_ids_and_tags():
    checker = make_checker([])
    present = make_nsg("nsg-1", [make_rule("ssh", port="22")], tags={"env": "prod"})
    other = make_nsg("nsg-3", [make_rule("ssh", port="22")], tags={"env": "dev"})
    by_name = {"nsg-1": present, "nsg-3": other}

    def get(resource_group, name):
        if name not in by_name:
            raise ResourceNotFoundError("not found")
        return by_name[name]
    checker._client.network_security_groups.get.side_effect = get

    assert checker.check(ids=[nsg_id("nsg-1"), nsg_id("nsg-2"), nsg_id("nsg-3")], tags={"env": ["prod", "stage"]})
    assert [nsg.name for nsg in checker.groups] == ["nsg-1"]
    checker._client.network_security_groups.get.assert_any_call("rg-1", "nsg-2")
    checker._client.network_security_groups.list_all.assert_not_called()


def test_check_failure():
    checker = make_checker([])
    error = HttpResponseError("forbidden")
    error.status_code = 403
    checker._client.network_security_groups.list_all.side_effect = error
    assert checker.check() is False
    assert checker.groups == []


def test_client_uses_account_wrapper():
    account = mock.Mock()
    checker = AzureNSGChecker(account=account, restricted_ports=RESTRICTED_PORTS)
    with mock.patch.dict("sys.modules", {"azure.mgmt.network": SimpleNamespace(NetworkManagementClient="NMC")}):
        assert checker.client is account.client.return_value
    account.client.assert_called_once_with("NMC")


def test_restrict():
    rules = [
        make_rule("world-ssh", source="*", port="22", priority=100),
        make_rule("mixed", source=None, sources=["Internet", "1.2.3.4/32", "5.6.7.8/32"], port="3389", priority=110),
        make_rule("mixed-single-left", source=None, sources=["0.0.0.0/0", "1.2.3.4/32"], port="21", priority=120),
        make_rule("private", source="10.0.0.0/8", port="22", priority=130),
    ]
    checker = make_checker([make_nsg("nsg-1", rules)])
    assert checker.check()
    nsg = checker.groups[0]
    client = mock.Mock()
    assert nsg.restrict(client) == 3

    calls = client.security_rules.begin_create_or_update.call_args_list
    assert [c[0][:3] for c in calls] == [("RG-1", "nsg-1", "world-ssh"),
                                         ("RG-1", "nsg-1", "mixed"),
                                         ("RG-1", "nsg-1", "mixed-single-left")]
    assert (rules[0].source_address_prefix, rules[0].source_address_prefixes) == ("VirtualNetwork", [])
    assert (rules[1].source_address_prefix, rules[1].source_address_prefixes) == (None, ["1.2.3.4/32", "5.6.7.8/32"])
    assert (rules[2].source_address_prefix, rules[2].source_address_prefixes) == ("1.2.3.4/32", [])
    assert rules[3].source_address_prefix == "10.0.0.0/8"
    assert client.security_rules.begin_create_or_update.return_value.result.call_count == 3


def test_restrict_failure():
    checker = make_checker([make_nsg("nsg-1", [make_rule("world-ssh", port="22")])])
    assert checker.check()
    client = mock.Mock()
    error = HttpResponseError("forbidden")
    error.status_code = 403
    client.security_rules.begin_create_or_update.side_effect = error
    assert checker.groups[0].restrict(client) is None


def test_backup_s3():
    checker = make_checker([make_nsg("nsg-1", [make_rule("world-ssh", port="22")])])
    assert checker.check()
    s3_client = mock.Mock()
    with mock.patch.object(network.S3Operations, "object_exists", return_value=False), \
         mock.patch.object(network.S3Operations, "put_object") as put_object:
        path = checker.groups[0].backup_s3(s3_client, "backup-bucket")
    assert path.startswith(f"azure_nsg/{SUBSCRIPTION}/RG-1/nsg-1_") and path.endswith(".json")
    args = put_object.call_args[0]
    assert args[:3] == (s3_client, "backup-bucket", path)
    assert json.loads(args[3])["security_rules"][0]["name"] == "world-ssh"


@pytest.fixture
def describe_env():
    import describe_azure_nsg_issues as describe
    config = mock.Mock()
    config.azureNsg.restricted_ports = RESTRICTED_PORTS
    config.azureNsg.in_whitelist.side_effect = lambda account_id, issue_id: issue_id == nsg_id("nsg-white").lower()
    config.azure.credentials = {"tenant_id": "t", "client_id": "c", "client_secret": "s"}
    nsgs = [
        make_nsg("nsg-open", [make_rule("world-ssh", port="22")]),
        make_nsg("nsg-white", [make_rule("world-rdp", port="3389")], rg="rg-1"),
        make_nsg("nsg-closed", [make_rule("private", source="10.0.0.0/8", port="22")]),
    ]
    stale = AzureNSGIssue(SUBSCRIPTION, nsg_id("nsg-removed").lower())
    with mock.patch.object(describe, "Config", return_value=config), \
         mock.patch.object(describe, "Account") as main_account, \
         mock.patch.object(describe, "IssueOperations") as ops, \
         mock.patch.object(describe, "DDB") as ddb, \
         mock.patch.object(AzureAccount, "credential", new_callable=mock.PropertyMock, return_value=object()), \
         mock.patch.object(AzureAccount, "client") as client:
        client.return_value.network_security_groups.list_all.return_value = nsgs
        ops.get_account_open_issues.return_value = [stale]
        yield SimpleNamespace(module=describe, config=config, ops=ops, ddb=ddb, stale=stale,
                              table=main_account.return_value.resource.return_value.Table.return_value)


def sns_event(payload):
    return {"Records": [{"Sns": {"Message": json.dumps(payload)}}]}


def test_describe_lambda(describe_env):
    payload = {"account_id": SUBSCRIPTION, "account_name": "azure-prod", "sns_arn": "arn:sns", "request_id": "req-1"}
    describe_env.module.lambda_handler(sns_event(payload), None)

    ops = describe_env.ops
    issues = {call[0][1].issue_id: call[0][1] for call in ops.update.call_args_list}
    assert set(issues) == {nsg_id("nsg-open").lower(), nsg_id("nsg-white").lower()}
    issue = issues[nsg_id("nsg-open").lower()]
    assert issue.account_id == SUBSCRIPTION
    assert issue.status == IssueStatus.Open
    assert issue.issue_details.provider == "azure"
    assert issue.issue_details.name == "nsg-open"
    assert issue.issue_details.location == "westeurope"
    assert issue.issue_details.resource_group == "RG-1"
    assert issue.issue_details.tags == {"owner": "alice"}
    assert issue.issue_details.rules == [
        {"name": "world-ssh", "protocol": "Tcp", "ports": "22", "source": "*", "priority": 100}]
    assert issues[nsg_id("nsg-white").lower()].status == IssueStatus.Whitelisted
    ops.set_status_resolved.assert_called_once_with(describe_env.table, describe_env.stale)
    describe_env.ddb.track_progress.assert_called_once_with(describe_env.table, "req-1")


def test_describe_lambda_check_failed_keeps_issues(describe_env):
    with mock.patch.object(describe_env.module.AzureNSGChecker, "check", return_value=False):
        describe_env.module.lambda_handler(sns_event({"account_id": SUBSCRIPTION, "account_name": "azure-prod",
                                                      "sns_arn": "arn:sns"}), None)
    describe_env.ops.update.assert_not_called()
    describe_env.ops.set_status_resolved.assert_not_called()
    describe_env.ddb.track_progress.assert_not_called()


def test_initiate_lambda():
    import initiate_to_desc_azure_nsg_issues as initiate
    config = mock.Mock()
    config.azureNsg.enabled = True
    config.azureNsg.accounts = {SUBSCRIPTION: "azure-prod", "sub-2": "azure-dev"}
    with mock.patch.dict(os.environ, {"SNS_ARN": "arn:sns"}), \
         mock.patch.object(initiate, "Config", return_value=config), \
         mock.patch.object(initiate, "Sns") as sns:
        initiate.lambda_handler({}, None)
        assert [c[0] for c in sns.publish.call_args_list] == [
            ("arn:sns", {"account_id": SUBSCRIPTION, "account_name": "azure-prod", "sns_arn": "arn:sns"}),
            ("arn:sns", {"account_id": "sub-2", "account_name": "azure-dev", "sns_arn": "arn:sns"}),
        ]

        sns.reset_mock()
        config.azureNsg.enabled = False
        initiate.lambda_handler({}, None)
        sns.publish.assert_not_called()


def test_reporting_description():
    module = load_script("reporting/create_azure_nsg_issue_tickets.py", "create_azure_nsg_issue_tickets")
    config = mock.Mock()
    config.whitelisting_procedure_url = None
    module_config = mock.Mock()
    module_config.provider = AzureAccount.provider
    module_config.remediation = False
    reporter = module.CreateAzureNSGTickets(config, module_config, AzureNSGIssue)
    issue = AzureNSGIssue(SUBSCRIPTION, nsg_id("nsg-1").lower())
    issue.issue_details.name = "nsg-1"
    issue.issue_details.location = "westeurope"
    issue.issue_details.resource_group = "rg-1"
    issue.issue_details.tags = {"owner": "alice"}
    issue.issue_details.network_interfaces = ["nic-1"]
    issue.issue_details.rules = [{"name": "world-ssh", "protocol": "Tcp", "ports": "22", "source": "*", "priority": 100}]

    assert reporter.issue_summary(issue, SUBSCRIPTION, "azure-prod") == \
        f"Azure NSG 'nsg-1' with unrestricted inbound access in 'azure-prod / {SUBSCRIPTION}' subscription"
    desc = reporter.build_description(issue, SUBSCRIPTION, "azure-prod", "alice")
    assert "*Risk*: High" in desc
    assert "*Cloud Provider*: Azure" in desc
    assert f"*Subscription ID*: {SUBSCRIPTION}" in desc
    assert "*Location*: westeurope" in desc
    assert "|world-ssh|100|Tcp|22|*|" in desc
    assert "|owner|alice|" in desc
    assert "*Attached network interfaces*: nic-1" in desc
    assert "*Recommendation*:" in desc
    assert reporter.get_labels() == ["azure-nsg-unrestricted-access"]


@pytest.fixture
def remediation():
    module = load_script("remediation/clean_azure_nsg_issues.py", "clean_azure_nsg_issues")
    config = mock.Mock()
    config.aws.s3_backup_bucket = "backup-bucket"
    config.azureNsg.restricted_ports = RESTRICTED_PORTS
    issue = AzureNSGIssue(SUBSCRIPTION, nsg_id("nsg-1").lower())
    issue.issue_details.name = "nsg-1"
    with mock.patch.object(module, "Account") as main_account, \
         mock.patch.object(module, "MultiCloudIssueRemediator") as remediator_cls, \
         mock.patch.object(module.AzureNSGChecker, "client", new_callable=mock.PropertyMock) as client:
        remediator = remediator_cls.return_value
        remediator.candidates.return_value = [(SUBSCRIPTION, "azure-prod", issue)]
        remediator.account.return_value.credential = object()
        cleaner = module.CleanAzureNSGIssues(config)
        yield SimpleNamespace(module=module, cleaner=cleaner, remediator=remediator, issue=issue,
                              client=client.return_value, s3=main_account.return_value.client.return_value)


def test_remediation_batch(remediation):
    rule = make_rule("world-ssh", port="22")
    remediation.client.network_security_groups.get.return_value = make_nsg("nsg-1", [rule], rg="rg-1")
    with mock.patch.object(network.AzureNSG, "backup_s3", return_value="azure_nsg/backup.json") as backup:
        remediation.cleaner.clean_azure_nsg_issues(batch=True)
    backup.assert_called_once_with(remediation.s3, "backup-bucket")
    remediation.client.security_rules.begin_create_or_update.assert_called_once_with("rg-1", "nsg-1", "world-ssh", rule)
    assert rule.source_address_prefix == "VirtualNetwork"
    args = remediation.remediator.report_remediation.call_args[0]
    assert args[:3] == (remediation.issue, SUBSCRIPTION, "azure-prod")
    assert "azure_nsg/backup.json" in args[3] and "was remediated by hammer" in args[3]
    assert args[4] is True


def test_remediation_interactive_declined(remediation):
    remediation.client.network_security_groups.get.return_value = make_nsg("nsg-1", [make_rule("world-ssh", port="22")])
    with mock.patch.object(remediation.module, "confirm", return_value=False) as confirm, \
         mock.patch.object(network.AzureNSG, "backup_s3") as backup:
        remediation.cleaner.clean_azure_nsg_issues(batch=False)
    confirm.assert_called_once()
    backup.assert_not_called()
    remediation.client.security_rules.begin_create_or_update.assert_not_called()
    remediation.remediator.report_remediation.assert_not_called()


@pytest.mark.parametrize("nsg", [None, make_nsg("nsg-1", [make_rule("private", source="10.0.0.0/8", port="22")])])
def test_remediation_skips_removed_or_fixed(remediation, nsg):
    if nsg is None:
        remediation.client.network_security_groups.get.side_effect = ResourceNotFoundError("not found")
    else:
        remediation.client.network_security_groups.get.return_value = nsg
    with mock.patch.object(network.AzureNSG, "backup_s3") as backup:
        remediation.cleaner.clean_azure_nsg_issues(batch=True)
    backup.assert_not_called()
    remediation.remediator.report_remediation.assert_not_called()


def test_remediation_failure_reported(remediation):
    remediation.client.network_security_groups.get.return_value = make_nsg("nsg-1", [make_rule("world-ssh", port="22")])
    error = HttpResponseError("conflict")
    error.status_code = 409
    remediation.client.security_rules.begin_create_or_update.side_effect = error
    with mock.patch.object(network.AzureNSG, "backup_s3", return_value="azure_nsg/backup.json"):
        remediation.cleaner.clean_azure_nsg_issues(batch=True)
    args = remediation.remediator.report_remediation.call_args[0]
    assert "Failed to remediate" in args[3]
    assert args[4] is False
