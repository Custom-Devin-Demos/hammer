import os
import sys
import json
import pytest


from datetime import datetime, timezone
from unittest import mock
from google.api_core import exceptions as gcp_exceptions
from google.cloud import compute_v1
from library import multicloud_reporting
from library.ddb_issues import IssueStatus, GCPUnencryptedDiskIssue
from library.gcp.compute import GCPDisk, GCPUnencryptedDisksChecker, resource_short_name
from library.gcp.utility import GCPAccount
from library.jiraoperations import NewIssue


import describe_gcp_unencrypted_disks as describe
import initiate_to_desc_gcp_unencrypted_disks as initiate


PROJECT_ID = "hammer-test-project"
PROJECT_NAME = "gcp-prod"
API = f"https://www.googleapis.com/compute/v1/projects/{PROJECT_ID}"
ZONE = "us-central1-a"


def make_disk(name, zone=ZONE, region=None, kms_key_name=None, sha256=None, labels=None, users=None):
    disk = compute_v1.Disk(
        name=name,
        status="READY",
        size_gb=10,
        type_=f"{API}/zones/{zone or 'us-central1-b'}/diskTypes/pd-standard",
        self_link=f"{API}/zones/{zone}/disks/{name}",
        labels=labels or {},
        users=users or [],
    )
    if zone:
        disk.zone = f"{API}/zones/{zone}"
    if region:
        disk.region = f"{API}/regions/{region}"
    if kms_key_name or sha256:
        disk.disk_encryption_key = compute_v1.CustomerEncryptionKey(kms_key_name=kms_key_name or "",
                                                                    sha256=sha256 or "")
    return disk


DISKS = {
    "google-managed": make_disk("google-managed",
                                labels={"owner": "alice", "bu": "news", "product": "web"},
                                users=[f"{API}/zones/{ZONE}/instances/instance-1"]),
    "cmek": make_disk("cmek", kms_key_name="projects/p/locations/global/keyRings/r/cryptoKeys/k"),
    "csek": make_disk("csek", sha256="cXVpY2sgYnJvd24gZm94"),
    "regional": make_disk("regional", zone=None, region="us-central1", labels={"env": "prod"}),
}


def aggregated_list(disks=None):
    disks = list(DISKS.values()) if disks is None else disks
    zonal = [disk for disk in disks if disk.zone]
    regional = [disk for disk in disks if not disk.zone]
    return [
        (f"zones/{ZONE}", compute_v1.DisksScopedList(disks=zonal)),
        ("zones/europe-west1-b", compute_v1.DisksScopedList()),
        ("regions/us-central1", compute_v1.DisksScopedList(disks=regional)),
    ]


def make_account(disks=None, side_effect=None):
    account = GCPAccount(PROJECT_ID, PROJECT_NAME, {"type": "service_account"})
    client = mock.Mock(name="DisksClient")
    if side_effect is not None:
        client.aggregated_list.side_effect = side_effect
    else:
        client.aggregated_list.return_value = aggregated_list(disks)
    account.client = mock.Mock(return_value=client)
    return account, client


def test_resource_short_name():
    assert resource_short_name(f"{API}/zones/{ZONE}") == ZONE
    assert resource_short_name("zones/us-east1-b/") == "us-east1-b"
    assert resource_short_name("") is None


def test_disk_properties():
    disk = GCPDisk(None, DISKS["google-managed"])
    assert disk.id == f"{ZONE}/google-managed"
    assert (disk.zone, disk.region, disk.location) == (ZONE, None, ZONE)
    assert disk.type == "pd-standard"
    assert disk.users == ["instance-1"]
    assert disk.tags == {"owner": "alice", "bu": "news", "product": "web"}
    assert (disk.encryption, disk.encrypted) == (GCPDisk.GOOGLE_MANAGED, False)

    regional = GCPDisk(None, DISKS["regional"])
    assert regional.id == "us-central1/regional"
    assert regional.location == "us-central1"


@pytest.mark.parametrize("name, encryption, encrypted", [
    ("google-managed", GCPDisk.GOOGLE_MANAGED, False),
    ("cmek", GCPDisk.CUSTOMER_MANAGED, True),
    ("csek", GCPDisk.CUSTOMER_SUPPLIED, True),
    ("regional", GCPDisk.GOOGLE_MANAGED, False),
])
def test_disk_encryption(name, encryption, encrypted):
    disk = GCPDisk(None, DISKS[name])
    assert disk.encryption == encryption
    assert disk.encrypted is encrypted


def test_check_collects_only_google_managed_disks():
    account, client = make_account()
    checker = GCPUnencryptedDisksChecker(account)

    assert checker.check()

    account.client.assert_called_once_with(compute_v1.DisksClient)
    client.aggregated_list.assert_called_once_with(request={"project": PROJECT_ID, "return_partial_success": True})
    assert sorted(disk.id for disk in checker.disks) == [f"{ZONE}/google-managed", "us-central1/regional"]
    assert checker.get_disk(f"{ZONE}/google-managed").name == "google-managed"
    assert checker.get_disk(f"{ZONE}/cmek") is None


def test_check_by_ids_returns_disks_regardless_of_encryption():
    account, _ = make_account()
    checker = GCPUnencryptedDisksChecker(account)

    assert checker.check(ids=[f"{ZONE}/cmek", f"{ZONE}/google-managed", f"{ZONE}/missing"])

    disks = {disk.id: disk for disk in checker.disks}
    assert sorted(disks) == [f"{ZONE}/cmek", f"{ZONE}/google-managed"]
    assert disks[f"{ZONE}/cmek"].encrypted
    assert not disks[f"{ZONE}/google-managed"].encrypted


@pytest.mark.parametrize("tags, expected", [
    ({"owner": "alice"}, [f"{ZONE}/google-managed"]),
    ({"env": ["dev", "prod"]}, ["us-central1/regional"]),
    ({"owner": "bob"}, []),
])
def test_check_by_tags(tags, expected):
    account, _ = make_account()
    checker = GCPUnencryptedDisksChecker(account)

    assert checker.check(tags=tags)

    assert sorted(disk.id for disk in checker.disks) == expected


@pytest.mark.parametrize("error", [
    gcp_exceptions.Forbidden("compute.disks.list denied"),
    gcp_exceptions.InternalServerError("boom"),
])
def test_check_api_errors(error):
    account, _ = make_account(side_effect=error)
    checker = GCPUnencryptedDisksChecker(account)

    assert not checker.check()
    assert checker.disks == []


def test_check_without_credentials():
    account = GCPAccount(PROJECT_ID, PROJECT_NAME, {})
    checker = GCPUnencryptedDisksChecker(account)

    assert not checker.check()


# identification lambdas
def sns_event(payload):
    return {"Records": [{"Sns": {"Message": json.dumps(payload)}}]}


def make_lambda_config(whitelist=()):
    config = mock.Mock()
    config.gcpDisk.ddb_table_name = "hammer-gcp-disks-unencrypted"
    config.gcpDisk.in_whitelist.side_effect = lambda account_id, issue_id: issue_id in whitelist
    config.gcp.credentials = {"type": "service_account"}
    config.api.ddb_table_name = "hammer-api-requests"
    return config


@pytest.fixture
def describe_env():
    """ Patch Config/DDB/IssueOperations and GCP client in describe lambda """
    client = mock.Mock(name="DisksClient")
    client.aggregated_list.return_value = aggregated_list()
    with mock.patch.object(describe, "Config") as config_cls, \
         mock.patch.object(describe, "Account") as account_cls, \
         mock.patch.object(describe, "IssueOperations") as ops, \
         mock.patch.object(describe, "DDB") as ddb, \
         mock.patch.object(GCPAccount, "credentials", new_callable=mock.PropertyMock) as credentials, \
         mock.patch.object(GCPAccount, "client", return_value=client) as account_client:
        config_cls.return_value = make_lambda_config()
        credentials.return_value = object()
        ops.get_account_open_issues.return_value = []
        yield mock.Mock(config_cls=config_cls, account_cls=account_cls, ops=ops, ddb=ddb,
                        credentials=credentials, client=client, account_client=account_client)


def payload(**kwargs):
    data = {"account_id": PROJECT_ID, "account_name": PROJECT_NAME, "sns_arn": "arn:aws:sns:topic"}
    data.update(kwargs)
    return data


def updated_issues(ops):
    return {call[0][1].issue_id: call[0][1] for call in ops.update.call_args_list}


def test_describe_creates_issues(describe_env):
    ops = describe_env.ops
    describe.lambda_handler(sns_event(payload()), None)

    describe_env.account_client.assert_called_once_with(compute_v1.DisksClient)
    ops.get_account_open_issues.assert_called_once_with(mock.ANY, PROJECT_ID, GCPUnencryptedDiskIssue)
    issues = updated_issues(ops)
    assert sorted(issues) == [f"{ZONE}/google-managed", "us-central1/regional"]
    issue = issues[f"{ZONE}/google-managed"]
    assert isinstance(issue, GCPUnencryptedDiskIssue)
    assert issue.account_id == PROJECT_ID
    assert issue.status == IssueStatus.Open
    assert issue.issue_details.as_dict() == {
        "provider": "gcp",
        "name": "google-managed",
        "location": ZONE,
        "status": "READY",
        "disk_type": "pd-standard",
        "size_gb": 10,
        "encryption": "google-managed",
        "users": ["instance-1"],
        "tags": {"owner": "alice", "bu": "news", "product": "web"},
    }
    ops.set_status_resolved.assert_not_called()
    describe_env.ddb.track_progress.assert_not_called()


def test_describe_whitelist_and_resolve(describe_env):
    ops = describe_env.ops
    describe_env.config_cls.return_value = make_lambda_config(whitelist=["us-central1/regional"])
    still_open = GCPUnencryptedDiskIssue(PROJECT_ID, f"{ZONE}/google-managed")
    vanished = GCPUnencryptedDiskIssue(PROJECT_ID, f"{ZONE}/deleted-or-encrypted")
    ops.get_account_open_issues.return_value = [still_open, vanished]

    describe.lambda_handler(sns_event(payload(request_id="req-1")), None)

    issues = updated_issues(ops)
    assert issues[f"{ZONE}/google-managed"].status == IssueStatus.Open
    assert issues["us-central1/regional"].status == IssueStatus.Whitelisted
    ops.set_status_resolved.assert_called_once_with(mock.ANY, vanished)
    describe_env.ddb.track_progress.assert_called_once_with(mock.ANY, "req-1")


def test_describe_check_failure_does_not_resolve(describe_env):
    ops = describe_env.ops
    describe_env.client.aggregated_list.side_effect = gcp_exceptions.Forbidden("denied")
    ops.get_account_open_issues.return_value = [GCPUnencryptedDiskIssue(PROJECT_ID, f"{ZONE}/google-managed")]

    describe.lambda_handler(sns_event(payload(request_id="req-1")), None)

    ops.update.assert_not_called()
    ops.set_status_resolved.assert_not_called()
    # API request progress is tracked even if check failed
    describe_env.ddb.track_progress.assert_called_once_with(mock.ANY, "req-1")


def test_describe_without_credentials(describe_env):
    describe_env.credentials.return_value = None

    describe.lambda_handler(sns_event(payload()), None)

    describe_env.account_client.assert_not_called()
    describe_env.ops.update.assert_not_called()


def test_describe_bad_event(describe_env):
    describe.lambda_handler({"Records": []}, None)

    describe_env.config_cls.assert_not_called()


@pytest.mark.parametrize("enabled, accounts", [
    (True, {"project-1": "one", "project-2": "two"}),
    (False, {"project-1": "one"}),
])
def test_initiate(enabled, accounts):
    with mock.patch.object(initiate, "Config") as config_cls, \
         mock.patch.object(initiate, "Sns") as sns, \
         mock.patch.dict(os.environ, {"SNS_ARN": "arn:aws:sns:topic"}):
        config_cls.return_value.gcpDisk.enabled = enabled
        config_cls.return_value.gcpDisk.accounts = accounts

        initiate.lambda_handler({}, None)

    if not enabled:
        sns.publish.assert_not_called()
        return
    published = [call[0] for call in sns.publish.call_args_list]
    assert published == [
        ("arn:aws:sns:topic", {"account_id": project_id, "account_name": name, "sns_arn": "arn:aws:sns:topic"})
        for project_id, name in accounts.items()
    ]


# reporting
@pytest.fixture
def reporting_module():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "hammer", "reporting-remediation"))
    try:
        from reporting import create_gcp_unencrypted_disk_issue_tickets
    finally:
        sys.path.pop(0)
    return create_gcp_unencrypted_disk_issue_tickets


def test_reporting_new_issue(reporting_module):
    config = mock.Mock()
    config.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    config.whitelisting_procedure_url = None
    config.gcpDisk.provider = GCPAccount.provider
    config.gcpDisk.name = "gcp_disk_unencrypted"
    config.gcpDisk.accounts = {PROJECT_ID: PROJECT_NAME}
    config.gcpDisk.remediation = False

    issue = GCPUnencryptedDiskIssue(PROJECT_ID, f"{ZONE}/google-managed")
    issue.issue_details.provider = "gcp"
    issue.issue_details.name = "google-managed"
    issue.issue_details.location = ZONE
    issue.issue_details.status = "READY"
    issue.issue_details.disk_type = "pd-standard"
    issue.issue_details.size_gb = 10
    issue.issue_details.encryption = "google-managed"
    issue.issue_details.users = ["instance-1"]
    issue.issue_details.tags = {"owner": "alice", "bu": "news", "product": "web"}

    reporter = reporting_module.CreateGCPUnencryptedDiskTickets(config)
    assert reporter.module_config is config.gcpDisk
    assert reporter.issue_class is GCPUnencryptedDiskIssue
    reporter.ddb_table = mock.Mock()
    reporter.jira = mock.Mock()
    reporter.jira.ticket_url.side_effect = lambda ticket: f"https://jira/{ticket}"
    reporter.jira.add_issue.return_value = NewIssue(ticket_id="SEC-1", ticket_assignee_id="alice")
    reporter.slack = mock.Mock()

    with mock.patch.object(multicloud_reporting, "IssueOperations") as ops:
        ops.get_account_not_closed_issues.return_value = [issue]
        reporter.create_tickets()

    ops.get_account_not_closed_issues.assert_called_once_with(reporter.ddb_table, PROJECT_ID,
                                                              GCPUnencryptedDiskIssue)
    kwargs = reporter.jira.add_issue.call_args[1]
    assert kwargs["issue_summary"] == (f"GCP unencrypted disk '{ZONE}/google-managed' "
                                       f"in '{PROJECT_NAME} / {PROJECT_ID}' project [news]")
    assert kwargs["labels"] == ["gcp-unencrypted-disks"]
    assert kwargs["priority"] == "Major"
    assert (kwargs["owner"], kwargs["bu"], kwargs["product"]) == ("alice", "news", "web")
    description = kwargs["issue_description"]
    assert description.startswith("GCP disk is encrypted only with Google-managed key")
    assert "*Risk*: High" in description
    assert "*Cloud Provider*: GCP" in description
    assert f"*Project ID*: {PROJECT_ID}" in description
    assert f"*Location*: {ZONE}" in description
    assert "|owner|alice|" in description
    assert f"|{ZONE}/google-managed|READY|pd-standard|10|google-managed|instance-1|" in description
    assert "*Recommendation*: Encrypt GCP disk with customer-managed encryption key" in description
    ops.set_status_reported.assert_called_once_with(reporter.ddb_table, issue)
    assert issue.jira_details.ticket == "SEC-1"
