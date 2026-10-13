import os
import sys
import json
import pytest


from datetime import datetime, timedelta, timezone
from unittest import mock
from botocore.exceptions import ClientError
from google.api_core import exceptions as google_exceptions
from google.cloud import compute_v1
from library.cloud import CloudProvider
from library.ddb_issues import IssueStatus, GCPFirewallIssue
from library import multicloud_reporting
from library.gcp.firewall import FirewallChecker, FirewallPermission, FirewallOperations, is_open_range
from library.jiraoperations import NewIssue

import describe_gcp_firewall_issues
import initiate_to_desc_gcp_firewall_issues

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hammer", "reporting-remediation"))
from reporting.create_gcp_firewall_issue_tickets import CreateGCPFirewallTickets  # noqa: E402
from remediation import clean_gcp_firewall_issues  # noqa: E402


PROJECT_ID = "example-prod-project"
PROJECT_NAME = "gcp-prod"
NETWORK = f"https://www.googleapis.com/compute/v1/projects/{PROJECT_ID}/global/networks/default"
restricted_ports = [21, 22, 23, 3389, 1433, 1521, 3306, 5432, 27017, 28017, 2375]


def firewall(name, allowed, source_ranges, direction="INGRESS", disabled=False, target_tags=None, priority=1000):
    return compute_v1.Firewall(
        name=name,
        network=NETWORK,
        direction=direction,
        disabled=disabled,
        priority=priority,
        allowed=[compute_v1.Allowed(I_p_protocol=protocol, ports=ports) for protocol, ports in allowed],
        source_ranges=source_ranges,
        target_tags=target_tags or [],
    )


# rule name -> (firewall, check should pass)
firewalls = {
    "open-ssh": (firewall("open-ssh", [("tcp", ["22"])], ["0.0.0.0/0"], target_tags=["web"]), False),
    "open-range-ipv6": (firewall("open-range-ipv6", [("tcp", ["3000-3400"])], ["10.0.0.0/8", "::/0"]), False),
    "open-all-protocols": (firewall("open-all-protocols", [("all", [])], ["0.0.0.0/0"]), False),
    "open-tcp-all-ports": (firewall("open-tcp-all-ports", [("tcp", [])], ["0.0.0.0/0"]), False),
    "open-udp-numeric": (firewall("open-udp-numeric", [("17", ["21"])], ["0.0.0.0/0"]), False),
    "open-mixed": (firewall("open-mixed", [("tcp", ["80", "443"]), ("udp", ["1433"])], ["0.0.0.0/0"]), False),
    "open-web": (firewall("open-web", [("tcp", ["80", "443"])], ["0.0.0.0/0"]), True),
    "open-icmp": (firewall("open-icmp", [("icmp", [])], ["0.0.0.0/0"]), True),
    "open-esp": (firewall("open-esp", [("esp", [])], ["0.0.0.0/0"]), True),
    "restricted-ssh": (firewall("restricted-ssh", [("tcp", ["22"])], ["35.235.240.0/20", "10.0.0.0/8"]), True),
    "disabled-ssh": (firewall("disabled-ssh", [("tcp", ["22"])], ["0.0.0.0/0"], disabled=True), True),
    "egress-ssh": (firewall("egress-ssh", [("tcp", ["22"])], [], direction="EGRESS"), True),
    "no-source-ranges": (firewall("no-source-ranges", [("tcp", ["22"])], []), True),
}


def make_account(firewalls_client):
    account = mock.Mock(name="gcp_account")
    account.id = PROJECT_ID
    account.name = PROJECT_NAME
    account.credentials = object()
    account.client.return_value = firewalls_client
    return account


def make_firewalls_client(rules=None):
    client = mock.Mock(name="firewalls_client")
    client.list.return_value = [fw for fw, _ in firewalls.values()] if rules is None else rules
    return client


@pytest.fixture
def checker():
    client = make_firewalls_client()
    checker = FirewallChecker(account=make_account(client), restricted_ports=restricted_ports)
    assert checker.check()
    client.list.assert_called_once_with(project=PROJECT_ID)
    return checker


def test_is_open_range():
    assert is_open_range("0.0.0.0/0")
    assert is_open_range("::/0")
    assert not is_open_range("8.8.8.8/32")
    assert not is_open_range("10.0.0.0/8")
    assert not is_open_range("not-a-cidr")


def test_permission_ports():
    assert FirewallPermission(compute_v1.Allowed(I_p_protocol="tcp", ports=["22", "80-90"])).port_ranges == \
           [(22, 22), (80, 90)]
    assert FirewallPermission(compute_v1.Allowed(I_p_protocol="tcp", ports=[])).port_ranges is None
    assert FirewallPermission(compute_v1.Allowed(I_p_protocol="all")).ports_str == "all"
    assert FirewallPermission(compute_v1.Allowed(I_p_protocol="TCP", ports=["22"])).protocol == "tcp"


@pytest.mark.parametrize("name", firewalls.keys())
def test_rule_check(checker, name):
    rule = checker.get_rule(name)
    assert rule is not None
    assert rule.restricted == firewalls[name][1], str(rule)


def test_rule_details(checker):
    rule = checker.get_rule("open-ssh")
    assert rule.network == "default"
    assert rule.target_tags == ["web"]
    assert rule.tags == {}
    assert rule.open_ranges == ["0.0.0.0/0"]
    assert rule.rules == [{"protocol": "tcp", "ports": "22", "source": "0.0.0.0/0", "priority": 1000}]

    rule = checker.get_rule("open-range-ipv6")
    assert rule.open_ranges == ["::/0"]
    assert rule.rules == [{"protocol": "tcp", "ports": "3000-3400", "source": "::/0", "priority": 1000}]

    rule = checker.get_rule("open-mixed")
    # only `allowed` entries with restricted ports are reported
    assert rule.rules == [{"protocol": "udp", "ports": "1433", "source": "0.0.0.0/0", "priority": 1000}]


def test_check_ids_and_tags():
    client = make_firewalls_client()
    checker = FirewallChecker(account=make_account(client), restricted_ports=restricted_ports)
    assert checker.check(ids=["open-ssh", "open-web"])
    assert sorted(rule.name for rule in checker.rules) == ["open-ssh", "open-web"]

    checker = FirewallChecker(account=make_account(client), restricted_ports=restricted_ports)
    assert checker.check(tags={"network": "web"})
    assert [rule.name for rule in checker.rules] == ["open-ssh"]


@pytest.mark.parametrize("error", [google_exceptions.Forbidden("denied"), google_exceptions.InternalServerError("boom")])
def test_check_failure(error):
    client = make_firewalls_client()
    client.list.side_effect = error
    checker = FirewallChecker(account=make_account(client), restricted_ports=restricted_ports)
    assert not checker.check()
    assert checker.rules == []


def test_restrict_removes_open_ranges(checker):
    client = checker.account.client.return_value
    rule = checker.get_rule("open-range-ipv6")
    assert rule.restrict() == 1
    kwargs = client.patch.call_args[1]
    assert kwargs["project"] == PROJECT_ID
    assert kwargs["firewall"] == "open-range-ipv6"
    assert list(kwargs["firewall_resource"].source_ranges) == ["10.0.0.0/8"]
    assert not kwargs["firewall_resource"].disabled
    client.patch.return_value.result.assert_called_once_with()


def test_restrict_disables_rule_without_remaining_ranges(checker):
    client = checker.account.client.return_value
    rule = checker.get_rule("open-ssh")
    assert rule.restrict() == 1
    resource = client.patch.call_args[1]["firewall_resource"]
    assert resource.disabled
    assert list(resource.source_ranges) == []


def test_restrict_restricted_and_failure(checker):
    client = checker.account.client.return_value
    assert checker.get_rule("open-web").restrict() == 0
    client.patch.assert_not_called()

    client.patch.side_effect = google_exceptions.Forbidden("denied")
    assert checker.get_rule("open-ssh").restrict() is None


def make_s3_client():
    s3_client = mock.Mock(name="s3_client")
    s3_client.head_object.side_effect = ClientError({"Error": {"Code": "404"}}, "HeadObject")
    return s3_client


def test_backup_s3(checker):
    s3_client = make_s3_client()
    path = checker.get_rule("open-ssh").backup_s3(s3_client, "backup-bucket")
    assert path.startswith(f"gcp_firewall/{PROJECT_ID}/open-ssh_") and path.endswith(".json")
    kwargs = s3_client.put_object.call_args[1]
    assert kwargs["Bucket"] == "backup-bucket"
    assert kwargs["Key"] == path
    body = json.loads(kwargs["Body"])
    assert body["name"] == "open-ssh"
    assert body["source_ranges"] == ["0.0.0.0/0"]


def test_find_source_s3():
    s3_client = mock.Mock(name="s3_client")
    prefix = f"gcp_firewall/{PROJECT_ID}/"
    s3_client.list_objects.return_value = {"Contents": [
        {"Key": f"{prefix}open-ssh_2026-01-01T00:00:00+00:00.json"},
        {"Key": f"{prefix}open-ssh_2026-02-01T00:00:00+00:00.json"},
        {"Key": f"{prefix}open-web_2026-03-01T00:00:00+00:00.json"},
    ]}
    downloaded = []

    def download(bucket, path, output):
        downloaded.append(path)
        output.write(json.dumps({"name": "open-ssh", "source_ranges": ["0.0.0.0/0"]}).encode())
    s3_client.download_fileobj.side_effect = download

    account = make_account(mock.Mock())
    source = FirewallOperations.find_source_s3(account, s3_client, "backup-bucket", "open-ssh")
    assert source["source_ranges"] == ["0.0.0.0/0"]
    assert downloaded == [f"{prefix}open-ssh_2026-02-01T00:00:00+00:00.json"]
    assert FirewallOperations.find_source_s3(account, s3_client, "backup-bucket", "missing") is None


def make_config(whitelist=()):
    config = mock.Mock(name="config")
    config.now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    config.whitelisting_procedure_url = None
    config.get_bu_by_name.return_value = None
    config.aws.s3_backup_bucket = "backup-bucket"
    module = config.gcpFirewall
    module.provider = CloudProvider.GCP
    module.name = "gcp_firewall_unrestricted_access"
    module.enabled = True
    module.remediation = True
    module.ddb_table_name = "hammer-gcp-firewall-unrestricted"
    module.restricted_ports = restricted_ports
    module.accounts = {PROJECT_ID: PROJECT_NAME, "example-dev-project": "gcp-dev"}
    module.remediation_accounts = {PROJECT_ID: PROJECT_NAME}
    module.remediation_retention_period = 0
    module.issue_retention_date = timedelta(days=21)
    module.in_whitelist.side_effect = lambda account_id, issue_id: issue_id in whitelist
    module.in_fixnow.return_value = False
    return config


def sns_event(payload):
    return {"Records": [{"Sns": {"Message": json.dumps(payload)}}]}


def test_initiate_lambda():
    config = make_config()
    with mock.patch.dict(os.environ, {"SNS_ARN": "arn:sns"}), \
         mock.patch.object(initiate_to_desc_gcp_firewall_issues, "Config", return_value=config), \
         mock.patch.object(initiate_to_desc_gcp_firewall_issues, "Sns") as sns:
        initiate_to_desc_gcp_firewall_issues.lambda_handler({}, None)
        assert sns.publish.call_args_list == [
            mock.call("arn:sns", {"account_id": PROJECT_ID, "account_name": PROJECT_NAME, "sns_arn": "arn:sns"}),
            mock.call("arn:sns", {"account_id": "example-dev-project", "account_name": "gcp-dev", "sns_arn": "arn:sns"}),
        ]

        config.gcpFirewall.enabled = False
        sns.publish.reset_mock()
        initiate_to_desc_gcp_firewall_issues.lambda_handler({}, None)
        sns.publish.assert_not_called()


def run_describe(config, firewalls_client, open_issues, request_id=None):
    gcp_account = make_account(firewalls_client)
    payload = {"account_id": PROJECT_ID, "account_name": PROJECT_NAME, "sns_arn": "arn:sns"}
    if request_id:
        payload["request_id"] = request_id
    with mock.patch.object(describe_gcp_firewall_issues, "Config", return_value=config), \
         mock.patch.object(describe_gcp_firewall_issues, "Account"), \
         mock.patch.object(describe_gcp_firewall_issues, "GCPAccount", return_value=gcp_account), \
         mock.patch.object(describe_gcp_firewall_issues, "DDB") as ddb, \
         mock.patch.object(describe_gcp_firewall_issues, "IssueOperations") as ops:
        ops.get_account_open_issues.return_value = open_issues
        describe_gcp_firewall_issues.lambda_handler(sns_event(payload), None)
        return ops, ddb


def test_describe_lambda():
    config = make_config(whitelist=("open-all-protocols",))
    stale = GCPFirewallIssue(PROJECT_ID, "removed-rule")
    still_open = GCPFirewallIssue(PROJECT_ID, "open-ssh")
    ops, ddb = run_describe(config, make_firewalls_client(), [stale, still_open], request_id="req-1")

    updated = {call[0][1].issue_id: call[0][1] for call in ops.update.call_args_list}
    expected = sorted(name for name, (_, passed) in firewalls.items() if not passed)
    assert sorted(updated) == expected

    issue = updated["open-ssh"]
    assert issue.account_id == PROJECT_ID
    assert issue.status == IssueStatus.Open
    details = issue.issue_details
    assert details.provider == "gcp"
    assert details.name == "open-ssh"
    assert details.location == "global"
    assert details.tags == {}
    assert details.network == "default"
    assert details.target_tags == ["web"]
    assert details.rules == [{"protocol": "tcp", "ports": "22", "source": "0.0.0.0/0", "priority": 1000}]
    assert updated["open-all-protocols"].status == IssueStatus.Whitelisted

    # only vanished issue is resolved
    assert [call[0][1].issue_id for call in ops.set_status_resolved.call_args_list] == ["removed-rule"]
    assert ddb.track_progress.call_args[0][1] == "req-1"


def test_describe_lambda_check_failure_keeps_issues():
    config = make_config()
    client = make_firewalls_client()
    client.list.side_effect = google_exceptions.Forbidden("denied")
    ops, ddb = run_describe(config, client, [GCPFirewallIssue(PROJECT_ID, "open-ssh")])
    ops.update.assert_not_called()
    ops.set_status_resolved.assert_not_called()
    ddb.track_progress.assert_not_called()


def make_issue(name="open-ssh", reported="2026-01-01T00:00:00+00:00"):
    issue = GCPFirewallIssue(PROJECT_ID, name)
    issue.status = IssueStatus.Open
    issue.issue_details.provider = "gcp"
    issue.issue_details.name = name
    issue.issue_details.location = "global"
    issue.issue_details.tags = {}
    issue.issue_details.network = "default"
    issue.issue_details.priority = 1000
    issue.issue_details.target_tags = ["web"]
    issue.issue_details.rules = [{"protocol": "tcp", "ports": "22", "source": "0.0.0.0/0", "priority": 1000}]
    issue.timestamps.reported = reported
    issue.jira_details.ticket = "SEC-1" if reported else None
    return issue


@pytest.fixture
def ops():
    with mock.patch.object(multicloud_reporting, "IssueOperations") as operations:
        yield operations


def test_reporting(ops):
    config = make_config()
    config.gcpFirewall.accounts = {PROJECT_ID: PROJECT_NAME}
    issue = make_issue(reported=None)
    ops.get_account_not_closed_issues.return_value = [issue]
    reporter = CreateGCPFirewallTickets(config)
    reporter.ddb_table = mock.Mock()
    reporter.jira = mock.Mock()
    reporter.jira.add_issue.return_value = NewIssue(ticket_id="SEC-2", ticket_assignee_id="bob")
    reporter.jira.ticket_url.side_effect = lambda ticket: f"https://jira/{ticket}"
    reporter.slack = mock.Mock()

    reporter.create_tickets()

    ops.get_account_not_closed_issues.assert_called_once_with(reporter.ddb_table, PROJECT_ID, GCPFirewallIssue)
    kwargs = reporter.jira.add_issue.call_args[1]
    assert kwargs["issue_summary"] == \
        f"GCP firewall rule 'open-ssh' with unrestricted access in '{PROJECT_NAME} / {PROJECT_ID}' project"
    assert kwargs["priority"] == "Critical"
    assert kwargs["labels"] == ["insecure-services", "gcp-firewall"]
    description = kwargs["issue_description"]
    for expected in ["*Risk*: High", "*Cloud Provider*: GCP", f"*Project ID*: {PROJECT_ID}",
                     "*GCP firewall rule*: open-ssh", "*Location*: global", "*Network*: default",
                     "*Target Tags*: web", "||Protocol||Ports||Source||", "|tcp|22|0.0.0.0/0|",
                     "*Recommendation*: Restrict source ranges", "Auto-Remediation Date"]:
        assert expected in description
    assert issue.jira_details.ticket == "SEC-2"
    ops.set_status_reported.assert_called_once_with(reporter.ddb_table, issue)


def run_remediation(ops, issues, firewalls_client, batch=True, whitelist=()):
    config = make_config(whitelist=whitelist)
    ops.get_account_open_issues.return_value = issues
    s3_client = make_s3_client()
    with mock.patch.object(clean_gcp_firewall_issues, "Account") as aws_account:
        aws_account.return_value.client.return_value = s3_client
        cleaner = clean_gcp_firewall_issues.CleanGCPFirewallIssues(config)
        remediator = cleaner.remediator
        remediator.ddb_table = mock.Mock()
        remediator.jira = mock.Mock()
        remediator.jira.ticket_url.side_effect = lambda ticket: f"https://jira/{ticket}"
        remediator.slack = mock.Mock()
        with mock.patch.object(remediator, "account", return_value=make_account(firewalls_client)):
            cleaner.clean_firewall_issues(batch=batch)
    return remediator, s3_client


def test_remediation(ops):
    issue = make_issue()
    client = make_firewalls_client([firewalls["open-ssh"][0]])
    remediator, s3_client = run_remediation(ops, [issue], client)

    s3_client.put_object.assert_called_once()
    assert client.patch.call_args[1]["firewall_resource"].disabled
    kwargs = remediator.jira.remediate_issue.call_args[1]
    assert kwargs["ticket_id"] == "SEC-1"
    assert kwargs["reassign"] is True
    assert "was remediated by hammer" in kwargs["comment"]
    assert f"gcp_firewall/{PROJECT_ID}/open-ssh_" in kwargs["comment"]
    remediator.slack.report_issue.assert_called_once()
    ops.set_status_remediated.assert_called_once_with(remediator.ddb_table, issue)


def test_remediation_failure_is_reported(ops):
    issue = make_issue()
    client = make_firewalls_client([firewalls["open-ssh"][0]])
    client.patch.side_effect = google_exceptions.Forbidden("denied")
    remediator, _ = run_remediation(ops, [issue], client)
    kwargs = remediator.jira.remediate_issue.call_args[1]
    assert kwargs["reassign"] is False
    assert "Failed to remediate" in kwargs["comment"]


@pytest.mark.parametrize("case", ["whitelisted", "not_reported", "removed", "fixed_by_user", "declined"])
def test_remediation_skipped(ops, case):
    issue = make_issue(reported=None if case == "not_reported" else "2026-01-01T00:00:00+00:00")
    rules = {
        "removed": [],
        "fixed_by_user": [firewall("open-ssh", [("tcp", ["22"])], ["10.0.0.0/8"])],
    }.get(case, [firewalls["open-ssh"][0]])
    client = make_firewalls_client(rules)
    with mock.patch.object(clean_gcp_firewall_issues, "confirm", return_value=False) as confirm:
        remediator, s3_client = run_remediation(ops, [issue], client,
                                                batch=case != "declined",
                                                whitelist=("open-ssh",) if case == "whitelisted" else ())
    if case == "declined":
        confirm.assert_called_once()
    client.patch.assert_not_called()
    s3_client.put_object.assert_not_called()
    remediator.jira.remediate_issue.assert_not_called()
    ops.set_status_remediated.assert_not_called()
