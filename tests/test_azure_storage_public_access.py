import os
import sys
import json
import pytest


from types import SimpleNamespace
from unittest import mock
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError
from library.cloud import CloudProvider
from library.ddb_issues import IssueStatus, AzureStoragePublicAccessIssue
from library.azure.storage import AzureStoragePublicAccessChecker, AzureStorageAccount, access_level
from library import multicloud_reporting


import describe_azure_storage_public_access
import initiate_to_desc_azure_storage_public_access


SUB_ID = "00000000-0000-0000-0000-000000000001"
SUB_NAME = "azure-prod"


def resource_id(name, rg="rg-1"):
    return f"/subscriptions/{SUB_ID}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}"


# storage account name -> (allow_blob_public_access, {container: public access level}, tags)
STORAGE_ACCOUNTS = {
    # public: account allows public access and has public containers
    "publicblob": (True, {"images": "Blob", "private": "None"}, {"owner": "alice", "bu": "news"}),
    "publiccontainer": (True, {"site": "Container"}, {}),
    # public: account level flag not set (old accounts default to allowed)
    "legacyunset": (None, {"web": "Blob"}, {}),
    # not public: account allows public access, but all containers are private
    "allprivate": (True, {"data": "None", "logs": None}, {}),
    # not public: public containers, but account level public access is disallowed
    "disallowed": (False, {"images": "Blob"}, {}),
    # not public: no containers
    "empty": (True, {}, {}),
}
PUBLIC = {"publicblob", "publiccontainer", "legacyunset"}


class FakeAccessLevel(object):
    """ mimics SDK `PublicAccess` enum """
    def __init__(self, value):
        self.value = value


def fake_storage_client(accounts=STORAGE_ACCOUNTS):
    client = mock.Mock(name="StorageManagementClient")
    client.storage_accounts.list.return_value = [
        SimpleNamespace(id=resource_id(name), name=name, location="westeurope", tags=tags,
                        allow_blob_public_access=allowed)
        for name, (allowed, _, tags) in accounts.items()
    ]

    def list_containers(resource_group, name):
        assert resource_group == "rg-1"
        return [SimpleNamespace(name=container, public_access=FakeAccessLevel(level) if level else None)
                for container, level in accounts[name][1].items()]
    client.blob_containers.list.side_effect = list_containers
    return client


def fake_azure_account(client):
    account = mock.Mock(name="AzureAccount")
    account.id = SUB_ID
    account.name = SUB_NAME
    account.provider = CloudProvider.AZURE
    account.client.return_value = client
    return account


def make_checker(client=None):
    client = client or fake_storage_client()
    checker = AzureStoragePublicAccessChecker(fake_azure_account(client))
    checker._client = client
    return checker


class AccessDenied(Exception):
    status_code = 403


def test_access_level():
    assert access_level(None) == "None"
    assert access_level("Blob") == "Blob"
    assert access_level(FakeAccessLevel("Container")) == "Container"


def test_check_detects_public_storage_accounts():
    checker = make_checker()
    assert checker.check()
    assert {sa.name for sa in checker.storage_accounts} == set(STORAGE_ACCOUNTS)
    assert {sa.name for sa in checker.storage_accounts if sa.public} == PUBLIC

    sa = checker.get_storage_account("publicblob")
    assert sa.public_containers == {"images": "Blob"}
    assert sa.resource_group == "rg-1"
    assert sa.location == "westeurope"
    assert sa.tags == {"owner": "alice", "bu": "news"}
    assert checker.get_storage_account("publiccontainer").public_containers == {"site": "Container"}
    assert checker.get_storage_account("disallowed").public_containers == {}
    assert checker.get_storage_account("missing") is None


def test_check_skips_containers_listing_when_public_access_disallowed():
    client = fake_storage_client()
    checker = make_checker(client)
    assert checker.check()
    listed = {call[0][1] for call in client.blob_containers.list.call_args_list}
    assert "disallowed" not in listed
    assert "publicblob" in listed


def test_check_filters_by_ids_and_tags():
    checker = make_checker()
    assert checker.check(ids=["publicblob", "allprivate"])
    assert {sa.name for sa in checker.storage_accounts} == {"publicblob", "allprivate"}

    checker = make_checker()
    assert checker.check(tags={"owner": ["alice"]})
    assert [sa.name for sa in checker.storage_accounts] == ["publicblob"]


def test_check_fails_when_storage_accounts_can_not_be_listed():
    client = fake_storage_client()
    client.storage_accounts.list.side_effect = AccessDenied("denied")
    checker = make_checker(client)
    assert not checker.check()
    assert checker.storage_accounts == []


def test_check_skips_storage_account_when_containers_can_not_be_listed():
    client = fake_storage_client()
    original = client.blob_containers.list.side_effect

    def list_containers(resource_group, name):
        if name == "publicblob":
            raise AccessDenied("denied")
        return original(resource_group, name)
    client.blob_containers.list.side_effect = list_containers
    checker = make_checker(client)
    assert checker.check()
    assert checker.get_storage_account("publicblob") is None
    assert checker.get_storage_account("publiccontainer").public


def test_checker_creates_storage_client_via_account():
    from azure.mgmt.storage import StorageManagementClient
    client = fake_storage_client()
    account = fake_azure_account(client)
    checker = AzureStoragePublicAccessChecker(account)
    assert checker.client is client
    account.client.assert_called_once_with(StorageManagementClient)


def test_restrict_makes_public_containers_private():
    client = fake_storage_client()
    checker = make_checker(client)
    checker.check(ids=["publicblob"])
    sa = checker.get_storage_account("publicblob")
    assert sa.restrict(client)

    client.blob_containers.update.assert_called_once()
    rg, name, container, params = client.blob_containers.update.call_args[0]
    assert (rg, name, container) == ("rg-1", "publicblob", "images")
    assert params.public_access == "None"

    client.storage_accounts.update.assert_called_once()
    rg, name, params = client.storage_accounts.update.call_args[0]
    assert (rg, name) == ("rg-1", "publicblob")
    assert params.allow_blob_public_access is False


def test_restrict_reports_failure():
    client = fake_storage_client()
    client.blob_containers.update.side_effect = Exception("boom")
    checker = make_checker(client)
    checker.check(ids=["publiccontainer"])
    sa = checker.get_storage_account("publiccontainer")
    assert not sa.restrict(client)
    # account level public access is still disabled
    client.storage_accounts.update.assert_called_once()


def no_such_key(*args, **kwargs):
    raise ClientError({"Error": {"Code": "404"}}, "HeadObject")


def test_backup_s3():
    sa = AzureStorageAccount(fake_azure_account(None), resource_id("publicblob"), "publicblob", "westeurope",
                             {}, True, {"images": "Blob", "private": "None"})
    s3_client = mock.Mock()
    s3_client.head_object.side_effect = no_such_key
    path = sa.backup_s3(s3_client, "backup-bucket")
    assert path.startswith(f"azure_storage_public_access/{SUB_ID}/publicblob_") and path.endswith(".json")

    kwargs = s3_client.put_object.call_args[1]
    assert kwargs["Bucket"] == "backup-bucket" and kwargs["Key"] == path and kwargs["ACL"] == "private"
    backup = json.loads(kwargs["Body"])
    assert backup["allow_blob_public_access"] is True
    assert backup["containers"] == {"images": "Blob", "private": "None"}
    assert backup["resource_group"] == "rg-1"


def test_backup_s3_does_not_overwrite():
    sa = AzureStorageAccount(fake_azure_account(None), resource_id("publicblob"), "publicblob", "westeurope",
                             {}, True, {"images": "Blob"})
    s3_client = mock.Mock()
    with pytest.raises(Exception):
        sa.backup_s3(s3_client, "backup-bucket")
    s3_client.put_object.assert_not_called()


# ---------------------------------------------------------------- identification lambdas

def test_initiate_lambda_publishes_each_subscription():
    config = mock.Mock()
    config.azureStoragePublic.enabled = True
    config.azureStoragePublic.accounts = {SUB_ID: SUB_NAME, "sub-2": "azure-dev"}
    with mock.patch.dict(os.environ, {"SNS_ARN": "arn:sns"}), \
         mock.patch.object(initiate_to_desc_azure_storage_public_access, "Config", return_value=config), \
         mock.patch.object(initiate_to_desc_azure_storage_public_access, "Sns") as sns:
        initiate_to_desc_azure_storage_public_access.lambda_handler({}, None)
    payloads = [call[0][1] for call in sns.publish.call_args_list]
    assert payloads == [
        {"account_id": SUB_ID, "account_name": SUB_NAME, "sns_arn": "arn:sns"},
        {"account_id": "sub-2", "account_name": "azure-dev", "sns_arn": "arn:sns"},
    ]


def test_initiate_lambda_disabled():
    config = mock.Mock()
    config.azureStoragePublic.enabled = False
    with mock.patch.dict(os.environ, {"SNS_ARN": "arn:sns"}), \
         mock.patch.object(initiate_to_desc_azure_storage_public_access, "Config", return_value=config), \
         mock.patch.object(initiate_to_desc_azure_storage_public_access, "Sns") as sns:
        initiate_to_desc_azure_storage_public_access.lambda_handler({}, None)
    sns.publish.assert_not_called()


def sns_event(payload):
    return {"Records": [{"Sns": {"Message": json.dumps(payload)}}]}


def run_describe(payload, open_issues=(), whitelist=(), credential=True):
    module = describe_azure_storage_public_access
    config = mock.Mock()
    config.azureStoragePublic.in_whitelist.side_effect = lambda account_id, issue_id: issue_id in whitelist
    account = fake_azure_account(fake_storage_client())
    account.credential = object() if credential else None
    with mock.patch.object(module, "Config", return_value=config), \
         mock.patch.object(module, "Account"), \
         mock.patch.object(module, "AzureAccount", return_value=account) as azure_account, \
         mock.patch.object(module, "DDB") as ddb, \
         mock.patch.object(module, "IssueOperations") as ops:
        ops.get_account_open_issues.return_value = list(open_issues)
        module.lambda_handler(sns_event(payload), None)
    return azure_account, ops, ddb


def test_describe_lambda_creates_issues():
    stale = AzureStoragePublicAccessIssue(SUB_ID, "deletedaccount")
    azure_account, ops, ddb = run_describe({"account_id": SUB_ID, "account_name": SUB_NAME},
                                           open_issues=[stale], whitelist=["publiccontainer"])
    assert azure_account.call_args[1]["id"] == SUB_ID

    issues = {call[0][1].issue_id: call[0][1] for call in ops.update.call_args_list}
    assert set(issues) == PUBLIC
    issue = issues["publicblob"]
    assert issue.account_id == SUB_ID
    assert issue.status == IssueStatus.Open
    assert issue.issue_details.provider == "azure"
    assert issue.issue_details.name == "publicblob"
    assert issue.issue_details.location == "westeurope"
    assert issue.issue_details.resource_group == "rg-1"
    assert issue.issue_details.resource_id == resource_id("publicblob")
    assert issue.issue_details.public_containers == {"images": "Blob"}
    assert issue.issue_details.tags == {"owner": "alice", "bu": "news"}
    assert issues["publiccontainer"].status == IssueStatus.Whitelisted

    resolved = [call[0][1].issue_id for call in ops.set_status_resolved.call_args_list]
    assert resolved == ["deletedaccount"]
    ddb.track_progress.assert_not_called()


def test_describe_lambda_keeps_still_public_issue_open():
    existing = AzureStoragePublicAccessIssue(SUB_ID, "publicblob")
    _, ops, _ = run_describe({"account_id": SUB_ID, "account_name": SUB_NAME}, open_issues=[existing])
    ops.set_status_resolved.assert_not_called()


def test_describe_lambda_tracks_api_request():
    _, _, ddb = run_describe({"account_id": SUB_ID, "account_name": SUB_NAME, "request_id": "req-1"})
    ddb.track_progress.assert_called_once()
    assert ddb.track_progress.call_args[0][1] == "req-1"


def test_describe_lambda_without_credential():
    _, ops, _ = run_describe({"account_id": SUB_ID, "account_name": SUB_NAME}, credential=False)
    ops.get_account_open_issues.assert_not_called()
    ops.update.assert_not_called()


# ---------------------------------------------------------------- reporting / remediation

def import_reporting_remediation(module):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "hammer", "reporting-remediation"))
    try:
        return __import__(module, fromlist=["*"])
    finally:
        sys.path.pop(0)


def make_config(remediation=False):
    config = mock.Mock()
    config.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    config.whitelisting_procedure_url = None
    config.get_bu_by_name.return_value = None
    module = config.azureStoragePublic
    module.provider = CloudProvider.AZURE
    module.name = "azure_storage_public_access"
    module.accounts = {SUB_ID: SUB_NAME}
    module.remediation_accounts = {SUB_ID: SUB_NAME}
    module.remediation = remediation
    module.issue_retention_date = timedelta(days=21)
    module.remediation_retention_period = 0
    module.in_whitelist.return_value = False
    module.in_fixnow.return_value = False
    config.aws.s3_backup_bucket = "backup-bucket"
    return config


def make_issue(name="publicblob", reported=None):
    issue = AzureStoragePublicAccessIssue(SUB_ID, name)
    issue.status = IssueStatus.Open
    issue.issue_details.provider = "azure"
    issue.issue_details.name = name
    issue.issue_details.location = "westeurope"
    issue.issue_details.resource_group = "rg-1"
    issue.issue_details.public_containers = {"images": "Blob"}
    issue.issue_details.tags = {"owner": "alice", "bu": "news", "product": "web"}
    issue.timestamps.reported = reported
    return issue


def test_reporting_new_issue():
    reporting = import_reporting_remediation("reporting.create_azure_storage_public_access_issue_tickets")
    reporter = reporting.CreateAzureStoragePublicAccessTickets(make_config(remediation=True))
    reporter.jira = mock.Mock()
    reporter.jira.add_issue.return_value = SimpleNamespace(ticket_id="SEC-1", ticket_assignee_id="alice")
    reporter.slack = mock.Mock()
    reporter.ddb_table = mock.Mock()
    issue = make_issue()
    with mock.patch.object(multicloud_reporting, "IssueOperations") as ops:
        ops.get_account_not_closed_issues.return_value = [issue]
        reporter.create_tickets_azure_storage_public_access()

    kwargs = reporter.jira.add_issue.call_args[1]
    assert kwargs["issue_summary"] == (f"Azure storage account 'publicblob' with public blob containers "
                                       f"in '{SUB_NAME} / {SUB_ID}' subscription [news]")
    assert kwargs["labels"] == ["azure-public-storage"]
    assert kwargs["owner"] == "alice" and kwargs["bu"] == "news" and kwargs["product"] == "web"
    desc = kwargs["issue_description"]
    for text in ("*Cloud Provider*: Azure", f"*Subscription ID*: {SUB_ID}", f"*Subscription Name*: {SUB_NAME}",
                 "*Location*: westeurope", "*Resource Group*: rg-1", "*Risk*: High",
                 "||Container||Public Access Level||", "|images|Blob|", "*Recommendation*",
                 "Auto-Remediation Date"):
        assert text in desc
    ops.set_status_reported.assert_called_once()
    assert issue.jira_details.ticket == "SEC-1"


def test_reporting_issue_changed():
    reporting = import_reporting_remediation("reporting.create_azure_storage_public_access_issue_tickets")
    reporter = reporting.CreateAzureStoragePublicAccessTickets(make_config())
    reporter.jira = mock.Mock()
    reporter.slack = mock.Mock()
    reporter.ddb_table = mock.Mock()
    issue = make_issue(reported="2026-01-01T00:00:00+00:00")
    issue.timestamps.updated = "2026-01-02T00:00:00+00:00"
    with mock.patch.object(multicloud_reporting, "IssueOperations") as ops:
        ops.get_account_not_closed_issues.return_value = [issue]
        reporter.create_tickets()
    reporter.jira.add_issue.assert_not_called()
    assert "|images|Blob|" in reporter.jira.update_issue.call_args[1]["comment"]
    ops.set_status_updated.assert_called_once()


def make_cleaner(storage_accounts=STORAGE_ACCOUNTS, issue_name="publicblob"):
    remediation = import_reporting_remediation("remediation.clean_azure_storage_public_access")
    config = make_config(remediation=True)
    cleaner = remediation.CleanAzureStoragePublicAccess(config)
    client = fake_storage_client(storage_accounts)
    cleaner.remediator = mock.Mock()
    cleaner.remediator.candidates.return_value = [(SUB_ID, SUB_NAME, make_issue(issue_name, reported="x"))]
    cleaner.remediator.account.return_value = fake_azure_account(client)
    cleaner.remediator.account_title.return_value = f"'{SUB_NAME} / {SUB_ID}' subscription"
    return remediation, cleaner, client


@pytest.mark.parametrize("batch", [True, False])
def test_remediation_restricts_public_storage_account(batch):
    remediation, cleaner, client = make_cleaner()
    with mock.patch.object(remediation, "Account") as main_account, \
         mock.patch.object(remediation, "confirm", return_value=True) as confirm:
        s3_client = main_account.return_value.client.return_value
        s3_client.head_object.side_effect = no_such_key
        cleaner.clean_azure_storage_public_access(batch=batch)

    assert confirm.called is (not batch)
    s3_client.put_object.assert_called_once()
    assert s3_client.put_object.call_args[1]["Bucket"] == "backup-bucket"
    client.blob_containers.update.assert_called_once()
    client.storage_accounts.update.assert_called_once()
    args = cleaner.remediator.report_remediation.call_args[0]
    assert args[1:3] == (SUB_ID, SUB_NAME)
    assert "was remediated by hammer" in args[3] and args[4] is True


def test_remediation_refused_in_interactive_mode():
    remediation, cleaner, client = make_cleaner()
    with mock.patch.object(remediation, "Account") as main_account, \
         mock.patch.object(remediation, "confirm", return_value=False):
        cleaner.clean_azure_storage_public_access(batch=False)
    main_account.return_value.client.return_value.put_object.assert_not_called()
    client.blob_containers.update.assert_not_called()
    cleaner.remediator.report_remediation.assert_not_called()


@pytest.mark.parametrize("issue_name", ["allprivate", "disallowed", "removedaccount"])
def test_remediation_skips_already_fixed(issue_name):
    remediation, cleaner, client = make_cleaner(issue_name=issue_name)
    with mock.patch.object(remediation, "Account") as main_account:
        cleaner.clean_azure_storage_public_access(batch=True)
    main_account.return_value.client.return_value.put_object.assert_not_called()
    client.blob_containers.update.assert_not_called()
    client.storage_accounts.update.assert_not_called()
    cleaner.remediator.report_remediation.assert_not_called()


def test_remediation_failure_is_reported():
    remediation, cleaner, client = make_cleaner()
    client.storage_accounts.update.side_effect = Exception("boom")
    with mock.patch.object(remediation, "Account") as main_account:
        main_account.return_value.client.return_value.head_object.side_effect = no_such_key
        cleaner.clean_azure_storage_public_access(batch=True)
    args = cleaner.remediator.report_remediation.call_args[0]
    assert "Failed to remediate" in args[3] and args[4] is False


def test_remediation_candidates_use_module_config():
    remediation = import_reporting_remediation("remediation.clean_azure_storage_public_access")
    config = make_config(remediation=True)
    cleaner = remediation.CleanAzureStoragePublicAccess(config)
    assert cleaner.remediator.module_config is config.azureStoragePublic
    assert cleaner.remediator.issue_class is AzureStoragePublicAccessIssue
