import os
import sys
import json
import pytest


from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from unittest import mock
from library.cloud import CloudProvider
from library.ddb_issues import IssueStatus, AzureStorageKeyRotationIssue
from library import multicloud_reporting
from library.azure import storage_keys
from library.azure.storage_keys import StorageKeysChecker, StorageKeyOperations
from library.jiraoperations import NewIssue


sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "hammer", "reporting-remediation"))

import describe_azure_storage_keys_rotation as describe_module  # noqa: E402
import initiate_to_desc_azure_storage_keys_rotation as initiate_module  # noqa: E402
from reporting import create_azure_storage_keys_rotation_issue_tickets as reporting_module  # noqa: E402
from remediation import clean_azure_storage_keys_rotation as remediation_module  # noqa: E402


SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000001"
SUBSCRIPTION_NAME = "azure-prod"

# starting point for checking if key expired
now = datetime(2026, 1, 1, tzinfo=timezone.utc)
# criteria for checking if key expired
rotation_criteria_days = timedelta(days=90)

fresh = now - rotation_criteria_days + timedelta(minutes=1)
stale = now - rotation_criteria_days - timedelta(minutes=1)


def storage_account(name, key1=fresh, key2=fresh, allow_shared_key_access=None, tags=None, no_key_creation_time=False):
    """ :return: object mimicking `azure.mgmt.storage.models.StorageAccount` """
    return SimpleNamespace(
        id=f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-{name}/providers/Microsoft.Storage/storageAccounts/{name}",
        name=name,
        location="westeurope",
        tags=tags,
        allow_shared_key_access=allow_shared_key_access,
        key_creation_time=None if no_key_creation_time else SimpleNamespace(key1=key1, key2=key2),
    )


# mocked Azure storage accounts with expected stale keys
storage_accounts = {
    "freshkeys": (storage_account("freshkeys"), []),
    "stalekey1": (storage_account("stalekey1", key1=stale, tags={"owner": "alice"}), ["key1"]),
    "stalekeys": (storage_account("stalekeys", key1=stale, key2=stale), ["key1", "key2"]),
    "unknownkey2": (storage_account("unknownkey2", key2=None), ["key2"]),
    "nocreationtime": (storage_account("nocreationtime", no_key_creation_time=True), ["key1", "key2"]),
    "isostrings": (storage_account("isostrings", key1=stale.isoformat(), key2=fresh.replace(tzinfo=None)), ["key1"]),
    "sharedkeydisabled": (storage_account("sharedkeydisabled", key1=stale, key2=None,
                                          allow_shared_key_access=False), []),
    "sharedkeyenabled": (storage_account("sharedkeyenabled", key1=stale, allow_shared_key_access=True), ["key1"]),
}


class FakeAzureAccount(object):
    provider = CloudProvider.AZURE

    def __init__(self, sources=None, list_error=None):
        self.id = SUBSCRIPTION_ID
        self.name = SUBSCRIPTION_NAME
        self.credential = object()
        self.storage_client = mock.Mock(name="StorageManagementClient")
        if list_error is not None:
            self.storage_client.storage_accounts.list.side_effect = list_error
        else:
            self.storage_client.storage_accounts.list.return_value = sources or []
        self.client = mock.Mock(return_value=self.storage_client)

    def __str__(self):
        return f"FakeAzureAccount(id='{self.id}')"


def all_sources():
    return [source for source, _ in storage_accounts.values()]


def run_checker(sources, **kwargs):
    checker = StorageKeysChecker(account=FakeAzureAccount(sources), now=now,
                                 rotation_criteria_days=rotation_criteria_days)
    assert checker.check(**kwargs)
    return checker


@pytest.mark.parametrize("name", storage_accounts.keys())
def test_stale_keys(name):
    source, expected = storage_accounts[name]
    checker = run_checker(all_sources())
    sa = checker.get_storage_account(name)
    assert sa is not None
    assert [key.name for key in sa.stale_keys] == expected
    assert sa.resource_group == f"rg-{name}"
    assert sa.location == "westeurope"


def test_checker_uses_storage_management_client():
    account = FakeAzureAccount(all_sources())
    checker = StorageKeysChecker(account=account, now=now, rotation_criteria_days=rotation_criteria_days)
    assert checker.check()
    from azure.mgmt.storage import StorageManagementClient
    account.client.assert_called_once_with(StorageManagementClient)
    assert len(checker.storage_accounts) == len(storage_accounts)


def test_checker_filters_ids_and_tags():
    checker = run_checker(all_sources(), ids=["stalekeys", "freshkeys"])
    assert sorted(sa.name for sa in checker.storage_accounts) == ["freshkeys", "stalekeys"]

    checker = run_checker(all_sources(), tags={"owner": ["alice", "bob"]})
    assert [sa.name for sa in checker.storage_accounts] == ["stalekey1"]
    assert checker.storage_accounts[0].tags == {"owner": "alice"}

    checker = run_checker(all_sources(), tags={"owner": "bob"})
    assert checker.storage_accounts == []


def test_checker_access_denied():
    err = Exception("forbidden")
    err.status_code = 403
    checker = StorageKeysChecker(account=FakeAzureAccount(list_error=err), now=now,
                                 rotation_criteria_days=rotation_criteria_days)
    assert checker.check() is False
    assert checker.storage_accounts == []


def test_checker_failure():
    checker = StorageKeysChecker(account=FakeAzureAccount(list_error=RuntimeError("boom")), now=now,
                                 rotation_criteria_days=rotation_criteria_days)
    assert checker.check() is False


def test_regenerate_key():
    client = mock.Mock()
    StorageKeyOperations.regenerate_key(client, "rg-1", "account1", "key2")
    args = client.storage_accounts.regenerate_key.call_args[0]
    assert args[:2] == ("rg-1", "account1")
    assert args[2].key_name == "key2"

    account = FakeAzureAccount([storage_accounts["stalekey1"][0]])
    checker = StorageKeysChecker(account=account, now=now, rotation_criteria_days=rotation_criteria_days)
    checker.check()
    checker.get_storage_account("stalekey1").regenerate_key("key1")
    args = account.storage_client.storage_accounts.regenerate_key.call_args[0]
    assert args[:2] == ("rg-stalekey1", "stalekey1")
    assert args[2].key_name == "key1"


# ------------------------------- identification lambdas -------------------------------

def make_config(whitelist=None, enabled=True):
    whitelist = whitelist or []
    config = mock.Mock(name="config")
    config.now = now
    config.aws.region = "eu-west-1"
    config.azure.credentials = {"tenant_id": "t", "client_id": "c", "client_secret": "s"}
    module = config.azureStorageKeys
    module.provider = CloudProvider.AZURE
    module.name = "azure_storage_keys_rotation"
    module.enabled = enabled
    module.accounts = {SUBSCRIPTION_ID: SUBSCRIPTION_NAME, "sub-2": "azure-dev"}
    module.remediation_accounts = {SUBSCRIPTION_ID: SUBSCRIPTION_NAME}
    module.remediation = True
    module.rotation_criteria_days = rotation_criteria_days
    module.issue_retention_date = timedelta(days=7)
    module.in_whitelist.side_effect = lambda account_id, issue_id: issue_id in whitelist
    return config


def sns_event(payload):
    return {"Records": [{"Sns": {"Message": json.dumps(payload)}}]}


def test_initiate_lambda():
    config = make_config()
    with mock.patch.dict(os.environ, {"SNS_ARN": "arn:sns"}), \
         mock.patch.object(initiate_module, "Config", return_value=config), \
         mock.patch.object(initiate_module, "Sns") as sns:
        initiate_module.lambda_handler({}, None)
    assert sns.publish.call_args_list == [
        mock.call("arn:sns", {"account_id": SUBSCRIPTION_ID, "account_name": SUBSCRIPTION_NAME, "sns_arn": "arn:sns"}),
        mock.call("arn:sns", {"account_id": "sub-2", "account_name": "azure-dev", "sns_arn": "arn:sns"}),
    ]


def test_initiate_lambda_disabled():
    with mock.patch.dict(os.environ, {"SNS_ARN": "arn:sns"}), \
         mock.patch.object(initiate_module, "Config", return_value=make_config(enabled=False)), \
         mock.patch.object(initiate_module, "Sns") as sns:
        initiate_module.lambda_handler({}, None)
    sns.publish.assert_not_called()


def run_describe(sources, open_issues=(), whitelist=None, request_id=None):
    config = make_config(whitelist)
    account = FakeAzureAccount(sources)
    payload = {"account_id": SUBSCRIPTION_ID, "account_name": SUBSCRIPTION_NAME, "sns_arn": "arn:sns"}
    if request_id:
        payload["request_id"] = request_id
    with mock.patch.object(describe_module, "Config", return_value=config), \
         mock.patch.object(describe_module, "Account") as aws_account, \
         mock.patch.object(describe_module, "AzureAccount", return_value=account) as azure_account, \
         mock.patch.object(describe_module, "DDB") as ddb, \
         mock.patch.object(describe_module, "IssueOperations") as ops:
        ops.get_account_open_issues.return_value = list(open_issues)
        describe_module.lambda_handler(sns_event(payload), None)
    azure_account.assert_called_once_with(id=SUBSCRIPTION_ID, name=SUBSCRIPTION_NAME,
                                          credentials=config.azure.credentials)
    return ops, ddb, aws_account


def test_describe_lambda():
    vanished = AzureStorageKeyRotationIssue(SUBSCRIPTION_ID, "removedaccount")
    rotated = AzureStorageKeyRotationIssue(SUBSCRIPTION_ID, "freshkeys")
    still_stale = AzureStorageKeyRotationIssue(SUBSCRIPTION_ID, "stalekeys")
    ops, ddb, _ = run_describe(all_sources(), open_issues=[vanished, rotated, still_stale], whitelist=["stalekeys"])

    issues = {call[0][1].issue_id: call[0][1] for call in ops.update.call_args_list}
    expected = {name for name, (_, keys) in storage_accounts.items() if keys}
    assert set(issues) == expected

    issue = issues["stalekey1"]
    assert issue.account_id == SUBSCRIPTION_ID
    assert issue.status == IssueStatus.Open
    assert issue.issue_details.provider == "azure"
    assert issue.issue_details.name == "stalekey1"
    assert issue.issue_details.location == "westeurope"
    assert issue.issue_details.resource_group == "rg-stalekey1"
    assert issue.issue_details.tags == {"owner": "alice"}
    assert issue.issue_details.keys == {"key1": stale.isoformat()}
    assert issue.issue_details.id.endswith("/storageAccounts/stalekey1")
    assert issues["nocreationtime"].issue_details.keys == {"key1": None, "key2": None}
    assert issues["stalekeys"].status == IssueStatus.Whitelisted

    resolved = [call[0][1].issue_id for call in ops.set_status_resolved.call_args_list]
    assert sorted(resolved) == ["freshkeys", "removedaccount"]
    ddb.track_progress.assert_not_called()


def test_describe_lambda_api_request():
    ops, ddb, _ = run_describe([storage_accounts["stalekey1"][0]], request_id="req-1")
    assert ops.update.call_count == 1
    assert ddb.track_progress.call_args[0][1] == "req-1"


def test_describe_lambda_check_failed_keeps_issues():
    config = make_config()
    err = Exception("forbidden")
    err.status_code = 403
    account = FakeAzureAccount(list_error=err)
    payload = {"account_id": SUBSCRIPTION_ID, "account_name": SUBSCRIPTION_NAME}
    with mock.patch.object(describe_module, "Config", return_value=config), \
         mock.patch.object(describe_module, "Account"), \
         mock.patch.object(describe_module, "AzureAccount", return_value=account), \
         mock.patch.object(describe_module, "IssueOperations") as ops:
        ops.get_account_open_issues.return_value = [AzureStorageKeyRotationIssue(SUBSCRIPTION_ID, "stalekey1")]
        describe_module.lambda_handler(sns_event(payload), None)
    ops.update.assert_not_called()
    ops.set_status_resolved.assert_not_called()


# ------------------------------------ reporting ------------------------------------

def make_issue(name="stalekey1", keys=None, reported=None, remediated=None, status=IssueStatus.Open):
    issue = AzureStorageKeyRotationIssue(SUBSCRIPTION_ID, name)
    issue.status = status
    issue.issue_details.provider = "azure"
    issue.issue_details.name = name
    issue.issue_details.location = "westeurope"
    issue.issue_details.resource_group = f"rg-{name}"
    issue.issue_details.tags = {"owner": "alice", "bu": "news", "product": "web"}
    issue.issue_details.keys = keys if keys is not None else {"key1": "2025-09-01T10:00:00+00:00", "key2": None}
    issue.timestamps.reported = reported
    issue.timestamps.remediated = remediated
    return issue


def test_reporting_new_issue():
    config = make_config()
    config.whitelisting_procedure_url = None
    config.get_bu_by_name.return_value = None
    reporter = reporting_module.CreateAzureStorageKeysRotationTickets(config)
    assert reporter.module_config is config.azureStorageKeys
    assert reporter.issue_class is AzureStorageKeyRotationIssue
    reporter.ddb_table = mock.Mock()
    reporter.jira = mock.Mock()
    reporter.jira.ticket_url.side_effect = lambda ticket: f"https://jira/{ticket}"
    reporter.slack = mock.Mock()
    issue = make_issue()
    reporter.jira.add_issue.return_value = NewIssue(ticket_id="SEC-17", ticket_assignee_id="alice")

    with mock.patch.object(multicloud_reporting, "IssueOperations") as ops:
        ops.get_account_not_closed_issues.side_effect = \
            lambda table, account_id, cls: [issue] if account_id == SUBSCRIPTION_ID else []
        reporter.create_tickets()
        ops.set_status_reported.assert_called_once_with(reporter.ddb_table, issue)

    kwargs = reporter.jira.add_issue.call_args[1]
    assert kwargs["issue_summary"] == (f"Azure storage account 'stalekey1' access keys have not been rotated "
                                       f"for 90 days in '{SUBSCRIPTION_NAME} / {SUBSCRIPTION_ID}' subscription [news]")
    assert kwargs["labels"] == ["azure-storage-keys-rotation"]
    assert kwargs["priority"] == "Major"
    assert (kwargs["owner"], kwargs["bu"], kwargs["product"]) == ("alice", "news", "web")
    description = kwargs["issue_description"]
    assert "*Risk*: Medium" in description
    assert "*Cloud Provider*: Azure" in description
    assert f"*Subscription ID*: {SUBSCRIPTION_ID}" in description
    assert "*Location*: westeurope" in description
    assert "*Resource Group*: rg-stalekey1" in description
    assert "||Key Name||Created||" in description
    assert "|key1|2025-09-01 10:00|" in description
    assert "|key2|unknown|" in description
    assert "Auto-Remediation Date" in description
    assert "*Recommendation*: Switch applications" in description
    assert issue.jira_details.ticket == "SEC-17"


# ----------------------------------- remediation -----------------------------------

def make_cleaner(issues, sources):
    config = make_config()
    cleaner = remediation_module.CleanAzureStorageKeysRotation(config)
    account = FakeAzureAccount(sources)
    remediator = mock.Mock()
    remediator.candidates.return_value = [(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, issue) for issue in issues]
    remediator.account.return_value = account
    remediator.account_title.return_value = f"'{SUBSCRIPTION_NAME} / {SUBSCRIPTION_ID}' subscription"
    cleaner.remediator = remediator
    return cleaner, account, remediator


def test_remediation_batch_regenerates_stale_keys():
    issues = [make_issue("stalekeys", reported="2025-01-01"), make_issue("freshkeys", reported="2025-01-01"),
              make_issue("removed", reported="2025-01-01")]
    cleaner, account, remediator = make_cleaner(issues, all_sources())
    with mock.patch.object(remediation_module, "confirm") as confirm:
        cleaner.clean_storage_keys(batch=True)
    confirm.assert_not_called()

    calls = account.storage_client.storage_accounts.regenerate_key.call_args_list
    assert [(call[0][1], call[0][2].key_name) for call in calls] == [("stalekeys", "key1"), ("stalekeys", "key2")]
    # fresh/removed accounts are not remediated
    assert remediator.report_remediation.call_count == 1
    args = remediator.report_remediation.call_args[0]
    assert args[0] is issues[0]
    assert args[1:3] == (SUBSCRIPTION_ID, SUBSCRIPTION_NAME)
    assert "was remediated by hammer" in args[3]
    assert args[4] is True


def test_remediation_interactive_refused():
    cleaner, account, remediator = make_cleaner([make_issue("stalekey1", reported="2025-01-01")], all_sources())
    with mock.patch.object(remediation_module, "confirm", return_value=False) as confirm:
        cleaner.clean_storage_keys(batch=False)
    confirm.assert_called_once()
    account.storage_client.storage_accounts.regenerate_key.assert_not_called()
    remediator.report_remediation.assert_not_called()


def test_remediation_interactive_confirmed():
    cleaner, account, remediator = make_cleaner([make_issue("stalekey1", reported="2025-01-01")], all_sources())
    with mock.patch.object(remediation_module, "confirm", return_value=True):
        cleaner.clean_storage_keys(batch=False)
    account.storage_client.storage_accounts.regenerate_key.assert_called_once()
    assert remediator.report_remediation.call_args[0][4] is True


def test_remediation_failure_is_reported():
    cleaner, account, remediator = make_cleaner([make_issue("stalekeys", reported="2025-01-01")], all_sources())
    account.storage_client.storage_accounts.regenerate_key.side_effect = [None, RuntimeError("denied")]
    cleaner.clean_storage_keys(batch=True)
    args = remediator.report_remediation.call_args[0]
    assert args[3].startswith("Failed to remediate stale access key(s) 'key2'")
    assert "'key1' were regenerated" in args[3]
    assert args[4] is False


def test_remediation_skips_when_check_fails():
    cleaner, account, remediator = make_cleaner([make_issue("stalekeys", reported="2025-01-01")], [])
    account.storage_client.storage_accounts.list.side_effect = RuntimeError("boom")
    cleaner.clean_storage_keys(batch=True)
    remediator.report_remediation.assert_not_called()


def test_storage_client_class_is_lazy():
    from azure.mgmt.storage import StorageManagementClient
    assert storage_keys.storage_client_class() is StorageManagementClient
