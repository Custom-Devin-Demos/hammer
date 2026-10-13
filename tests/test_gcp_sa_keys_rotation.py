import os
import sys
import json
import pytest


from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock
from library.cloud import CloudProvider
from library.ddb_issues import IssueStatus, GCPServiceAccountKeyIssue
from library.gcp import iam as gcp_iam
from library.gcp.iam import GCPServiceAccountKeyChecker, GCPIAMOperations
from library.gcp.utility import GCPAccount
from library import multicloud_reporting


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "hammer", "reporting-remediation"))

import describe_gcp_sa_keys_rotation  # noqa: E402
import initiate_to_desc_gcp_sa_keys_rotation  # noqa: E402
from reporting.create_gcp_sa_keys_rotation_issue_tickets import CreateGCPServiceAccountKeyRotationTickets  # noqa: E402
from remediation.clean_gcp_sa_keys_rotation import CleanGCPServiceAccountStaleKeys  # noqa: E402
from remediation import clean_gcp_sa_keys_rotation  # noqa: E402


PROJECT_ID = "hammer-test-project"
PROJECT_NAME = "test-project"
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
ROTATION = timedelta(days=90)

SA_APP = f"app@{PROJECT_ID}.iam.gserviceaccount.com"
SA_CI = f"ci@{PROJECT_ID}.iam.gserviceaccount.com"


def sa_name(email):
    return f"projects/{PROJECT_ID}/serviceAccounts/{email}"


def key_name(email, key_id):
    return f"{sa_name(email)}/keys/{key_id}"


def make_key(email, key_id, age_days, disabled=False, key_type="USER_MANAGED", expires=None):
    return SimpleNamespace(
        name=key_name(email, key_id),
        valid_after_time=None if age_days is None else NOW - timedelta(days=age_days),
        valid_before_time=expires,
        disabled=disabled,
        key_type=SimpleNamespace(name=key_type),
    )


# key id -> (expected stale, key)
KEYS = {
    SA_APP: [
        # created long time ago - stale
        (True, make_key(SA_APP, "app-old", 200)),
        # fresh key
        (False, make_key(SA_APP, "app-new", 10)),
        # old, but disabled
        (False, make_key(SA_APP, "app-old-disabled", 300, disabled=True)),
        # exactly on the edge - not stale
        (False, make_key(SA_APP, "app-edge", 90)),
    ],
    SA_CI: [
        (True, make_key(SA_CI, "ci-old", 91, expires=NOW + timedelta(days=10))),
        # system managed keys are rotated by Google
        (False, make_key(SA_CI, "ci-system", 500, key_type="SYSTEM_MANAGED")),
        # unknown creation time
        (False, make_key(SA_CI, "ci-unknown", None)),
    ],
}


def make_iam_client(keys=KEYS):
    client = mock.Mock()
    client.list_service_accounts.return_value = [
        SimpleNamespace(name=sa_name(email), email=email, unique_id=str(i), display_name=email.split("@")[0],
                        disabled=False)
        for i, email in enumerate(keys)
    ]

    def list_keys(request):
        email = request["name"].rsplit("/", 1)[-1]
        assert request["key_types"] == ["USER_MANAGED"]
        return SimpleNamespace(keys=[key for _, key in keys[email]])

    client.list_service_account_keys.side_effect = list_keys
    return client


def make_account(client):
    account = GCPAccount(PROJECT_ID, PROJECT_NAME, credentials={"type": "service_account"})
    account._credentials = object()
    account.client = mock.Mock(return_value=client)
    return account


def expected_stale():
    return {key.name for email in KEYS for stale, key in KEYS[email] if stale}


class AccessDenied(Exception):
    pass


AccessDenied.__name__ = "PermissionDenied"


def test_checker_detects_stale_keys():
    client = make_iam_client()
    checker = GCPServiceAccountKeyChecker(make_account(client), now=NOW, rotation_criteria_days=ROTATION)
    assert checker.check()
    client.list_service_accounts.assert_called_once_with(request={"name": f"projects/{PROJECT_ID}"})
    assert {key.name for key in checker.stale_keys} == expected_stale()
    # system managed keys are filtered out
    assert checker.get_key("ci-system") is None
    assert len(checker.service_accounts) == 2
    key = checker.get_key("ci-old")
    assert key.service_account.email == SA_CI
    assert key.age_days == 91
    assert key.expires == NOW + timedelta(days=10)


def test_checker_no_issues():
    keys = {SA_APP: [(False, make_key(SA_APP, "fresh", 1))]}
    checker = GCPServiceAccountKeyChecker(make_account(make_iam_client(keys)), now=NOW, rotation_criteria_days=ROTATION)
    assert checker.check()
    assert checker.stale_keys == []


def test_checker_ids_filter():
    checker = GCPServiceAccountKeyChecker(make_account(make_iam_client()), now=NOW, rotation_criteria_days=ROTATION)
    assert checker.check(ids=[SA_CI])
    assert {key.name for key in checker.stale_keys} == {key_name(SA_CI, "ci-old")}
    checker = GCPServiceAccountKeyChecker(make_account(make_iam_client()), now=NOW, rotation_criteria_days=ROTATION)
    assert checker.check(ids=[key_name(SA_APP, "app-old")])
    assert {key.name for key in checker.stale_keys} == {key_name(SA_APP, "app-old")}


def test_checker_access_denied():
    client = make_iam_client()
    client.list_service_accounts.side_effect = AccessDenied("denied")
    checker = GCPServiceAccountKeyChecker(make_account(client), now=NOW, rotation_criteria_days=ROTATION)
    assert not checker.check()

    client = make_iam_client()
    client.list_service_account_keys.side_effect = RuntimeError("boom")
    checker = GCPServiceAccountKeyChecker(make_account(client), now=NOW, rotation_criteria_days=ROTATION)
    assert not checker.check()


def test_iam_client_uses_account_credentials():
    account = make_account(mock.Mock())
    from google.cloud import iam_admin_v1
    GCPIAMOperations.iam_client(account)
    account.client.assert_called_once_with(iam_admin_v1.IAMClient)


def test_as_utc_datetime():
    naive = datetime(2020, 1, 1)
    assert gcp_iam.as_utc_datetime(naive).tzinfo == timezone.utc
    assert gcp_iam.as_utc_datetime(None) is None
    from google.protobuf.timestamp_pb2 import Timestamp
    assert gcp_iam.as_utc_datetime(Timestamp()) is None
    ts = Timestamp(seconds=1577836800)
    assert gcp_iam.as_utc_datetime(ts) == datetime(2020, 1, 1, tzinfo=timezone.utc)


def test_key_disable():
    client = make_iam_client()
    checker = GCPServiceAccountKeyChecker(make_account(client), now=NOW, rotation_criteria_days=ROTATION)
    assert checker.check()
    checker.get_key("app-old").disable()
    client.disable_service_account_key.assert_called_once_with(request={"name": key_name(SA_APP, "app-old")})


def test_get_service_account_key_not_found():
    class NotFound(Exception):
        pass
    client = mock.Mock()
    client.get_service_account_key.side_effect = NotFound()
    assert GCPIAMOperations.get_service_account_key(client, "k") is None
    client.get_service_account_key.side_effect = RuntimeError()
    with pytest.raises(RuntimeError):
        GCPIAMOperations.get_service_account_key(client, "k")


# ---------- identification lambdas ----------

def make_lambda_config(whitelist=()):
    config = mock.Mock()
    config.now = NOW
    config.gcp.credentials = {"type": "service_account"}
    module = config.gcpServiceAccountKeys
    module.enabled = True
    module.accounts = {PROJECT_ID: PROJECT_NAME, "other-project": "other"}
    module.ddb_table_name = "hammer-gcp-sa-keys-rotation"
    module.rotation_criteria_days = ROTATION
    module.in_whitelist.side_effect = lambda account_id, issue_id: issue_id in whitelist
    return config


def sns_event(payload):
    return {"Records": [{"Sns": {"Message": json.dumps(payload)}}]}


def test_initiate_lambda():
    config = make_lambda_config()
    with mock.patch.object(initiate_to_desc_gcp_sa_keys_rotation, "Config", return_value=config), \
         mock.patch.object(initiate_to_desc_gcp_sa_keys_rotation, "Sns") as sns, \
         mock.patch.dict(os.environ, {"SNS_ARN": "arn:sns"}):
        initiate_to_desc_gcp_sa_keys_rotation.lambda_handler({}, None)
    assert sns.publish.call_args_list == [
        mock.call("arn:sns", {"account_id": PROJECT_ID, "account_name": PROJECT_NAME, "sns_arn": "arn:sns"}),
        mock.call("arn:sns", {"account_id": "other-project", "account_name": "other", "sns_arn": "arn:sns"}),
    ]


def test_initiate_lambda_disabled():
    config = make_lambda_config()
    config.gcpServiceAccountKeys.enabled = False
    with mock.patch.object(initiate_to_desc_gcp_sa_keys_rotation, "Config", return_value=config), \
         mock.patch.object(initiate_to_desc_gcp_sa_keys_rotation, "Sns") as sns, \
         mock.patch.dict(os.environ, {"SNS_ARN": "arn:sns"}):
        initiate_to_desc_gcp_sa_keys_rotation.lambda_handler({}, None)
    sns.publish.assert_not_called()


def run_describe(config, client, open_issues=(), payload=None):
    payload = payload or {"account_id": PROJECT_ID, "account_name": PROJECT_NAME}
    module = describe_gcp_sa_keys_rotation
    account = make_account(client)
    with mock.patch.object(module, "Config", return_value=config), \
         mock.patch.object(module, "Account"), \
         mock.patch.object(module, "DDB") as ddb, \
         mock.patch.object(module, "GCPAccount", return_value=account) as account_cls, \
         mock.patch.object(module, "IssueOperations") as ops:
        ops.get_account_open_issues.return_value = list(open_issues)
        module.lambda_handler(sns_event(payload), None)
    account_cls.assert_called_once_with(id=PROJECT_ID, name=PROJECT_NAME, credentials=config.gcp.credentials)
    return ops, ddb


def test_describe_lambda_creates_and_resolves_issues():
    vanished = GCPServiceAccountKeyIssue(PROJECT_ID, key_name(SA_APP, "deleted-key"))
    still_open = GCPServiceAccountKeyIssue(PROJECT_ID, key_name(SA_APP, "app-old"))
    ops, ddb = run_describe(make_lambda_config(whitelist=(SA_CI,)), make_iam_client(),
                            open_issues=[vanished, still_open])

    updated = {call[0][1].issue_id: call[0][1] for call in ops.update.call_args_list}
    assert set(updated) == expected_stale()

    issue = updated[key_name(SA_APP, "app-old")]
    assert issue.account_id == PROJECT_ID
    assert issue.status == IssueStatus.Open
    details = issue.issue_details
    assert details.provider == "gcp"
    assert details.name == f"{SA_APP}/app-old"
    assert details.location == "global"
    assert details.tags == {}
    assert details.service_account == SA_APP
    assert details.key_id == "app-old"
    assert details.created == (NOW - timedelta(days=200)).isoformat()
    assert details.expires is None

    # service account in whitelist
    assert updated[key_name(SA_CI, "ci-old")].status == IssueStatus.Whitelisted
    assert updated[key_name(SA_CI, "ci-old")].issue_details.expires == (NOW + timedelta(days=10)).isoformat()

    ops.set_status_resolved.assert_called_once_with(mock.ANY, vanished)
    ddb.track_progress.assert_not_called()


def test_describe_lambda_key_whitelist_and_api_tracking():
    whitelisted = key_name(SA_APP, "app-old")
    ops, ddb = run_describe(make_lambda_config(whitelist=(whitelisted,)), make_iam_client(),
                            payload={"account_id": PROJECT_ID, "account_name": PROJECT_NAME, "request_id": "req-1"})
    statuses = {call[0][1].issue_id: call[0][1].status for call in ops.update.call_args_list}
    assert statuses[whitelisted] == IssueStatus.Whitelisted
    assert statuses[key_name(SA_CI, "ci-old")] == IssueStatus.Open
    ddb.track_progress.assert_called_once_with(mock.ANY, "req-1")


def test_describe_lambda_check_failure_keeps_issues():
    client = make_iam_client()
    client.list_service_accounts.side_effect = AccessDenied()
    existing = GCPServiceAccountKeyIssue(PROJECT_ID, key_name(SA_APP, "app-old"))
    ops, _ = run_describe(make_lambda_config(), client, open_issues=[existing])
    client.list_service_accounts.assert_called_once()
    ops.get_account_open_issues.assert_called_once()
    ops.update.assert_not_called()
    ops.set_status_resolved.assert_not_called()


def test_describe_lambda_bad_event():
    with mock.patch.object(describe_gcp_sa_keys_rotation, "Config") as config:
        describe_gcp_sa_keys_rotation.lambda_handler({}, None)
    config.assert_not_called()


# ---------- reporting ----------

def make_module_config(remediation=True):
    module = mock.Mock()
    module.provider = CloudProvider.GCP
    module.name = "gcp_sa_keys_rotation"
    module.accounts = {PROJECT_ID: PROJECT_NAME}
    module.remediation_accounts = module.accounts
    module.remediation = remediation
    module.rotation_criteria_days = ROTATION
    module.issue_retention_date = timedelta(days=7)
    module.remediation_retention_period = 7
    module.in_whitelist.return_value = False
    module.in_fixnow.return_value = False
    return module


def make_reporting_config():
    config = mock.Mock()
    config.now = NOW
    config.whitelisting_procedure_url = None
    config.get_bu_by_name.return_value = None
    return config


def make_issue(key_id="app-old", email=SA_APP, reported=None, status=IssueStatus.Open):
    issue = GCPServiceAccountKeyIssue(PROJECT_ID, key_name(email, key_id))
    issue.status = status
    issue.issue_details.provider = "gcp"
    issue.issue_details.name = f"{email}/{key_id}"
    issue.issue_details.location = "global"
    issue.issue_details.tags = {}
    issue.issue_details.service_account = email
    issue.issue_details.key_id = key_id
    issue.issue_details.created = (NOW - timedelta(days=200)).isoformat()
    issue.timestamps.reported = reported
    return issue


def test_reporting_new_issue():
    reporter = CreateGCPServiceAccountKeyRotationTickets(make_reporting_config(), make_module_config(),
                                                         GCPServiceAccountKeyIssue)
    reporter.jira = mock.Mock()
    reporter.jira.add_issue.return_value = SimpleNamespace(ticket_id="SEC-1", ticket_assignee_id="bob")
    reporter.slack = mock.Mock()
    reporter.ddb_table = mock.Mock()
    issue = make_issue()
    with mock.patch.object(multicloud_reporting, "IssueOperations") as ops:
        ops.get_account_not_closed_issues.return_value = [issue]
        reporter.create_tickets()
        ops.set_status_reported.assert_called_once_with(reporter.ddb_table, issue)

    kwargs = reporter.jira.add_issue.call_args[1]
    assert kwargs["issue_summary"] == (f"GCP service account key '{SA_APP}/app-old' rotation required "
                                       f"in '{PROJECT_NAME} / {PROJECT_ID}' project")
    assert kwargs["labels"] == ["gcp-sa-key-rotation"]
    assert kwargs["account_id"] == PROJECT_ID
    desc = kwargs["issue_description"]
    assert "*Cloud Provider*: GCP" in desc
    assert f"*Project ID*: {PROJECT_ID}" in desc
    assert "*Location*: global" in desc
    assert "*Risk*: High" in desc
    assert "more than 90 days ago" in desc
    assert f"|{SA_APP}|app-old|{key_name(SA_APP, 'app-old')}|" in desc
    assert "|200|never|" in desc
    assert "*Auto-Remediation Date*" in desc
    assert "*Recommendation*: Rotate the service account key" in desc
    assert issue.jira_details.ticket == "SEC-1"


def test_reporting_key_age_unknown():
    reporter = CreateGCPServiceAccountKeyRotationTickets(make_reporting_config(), make_module_config(),
                                                         GCPServiceAccountKeyIssue)
    issue = make_issue()
    issue.issue_details.created = None
    assert reporter.key_age(issue) == "unknown"


# ---------- remediation ----------

def make_remediator():
    remediator = CleanGCPServiceAccountStaleKeys(make_reporting_config(), make_module_config(),
                                                 GCPServiceAccountKeyIssue)
    remediator.jira = mock.Mock()
    remediator.slack = mock.Mock()
    remediator.ddb_table = mock.Mock()
    return remediator


@pytest.fixture
def remediation_env():
    client = mock.Mock()
    client.get_service_account_key.return_value = SimpleNamespace(disabled=False)
    account = make_account(client)
    with mock.patch.object(multicloud_reporting, "IssueOperations") as ops, \
         mock.patch.object(CleanGCPServiceAccountStaleKeys, "account", return_value=account), \
         mock.patch.object(GCPIAMOperations, "iam_client", return_value=client):
        yield ops, client


def test_remediation_disables_key(remediation_env):
    ops, client = remediation_env
    issue = make_issue(reported=(NOW - timedelta(days=30)).isoformat())
    ops.get_account_open_issues.return_value = [issue]
    remediator = make_remediator()
    remediator.clean_service_account_keys(batch=True)

    client.disable_service_account_key.assert_called_once_with(request={"name": issue.issue_id})
    remediator.jira.remediate_issue.assert_called_once()
    assert remediator.jira.remediate_issue.call_args[1]["reassign"] is True
    assert "was remediated by hammer" in remediator.jira.remediate_issue.call_args[1]["comment"]
    remediator.slack.report_issue.assert_called_once()
    ops.set_status_remediated.assert_called_once_with(remediator.ddb_table, issue)


def test_remediation_failure_reported(remediation_env):
    ops, client = remediation_env
    client.disable_service_account_key.side_effect = RuntimeError("boom")
    issue = make_issue(reported=(NOW - timedelta(days=30)).isoformat())
    ops.get_account_open_issues.return_value = [issue]
    remediator = make_remediator()
    remediator.clean_service_account_keys(batch=True)
    kwargs = remediator.jira.remediate_issue.call_args[1]
    assert kwargs["reassign"] is False
    assert "Failed to remediate" in kwargs["comment"]
    ops.set_status_remediated.assert_called_once()


def test_remediation_skips(remediation_env):
    ops, client = remediation_env
    not_reported = make_issue("k1")
    too_recent = make_issue("k2", reported=(NOW - timedelta(days=1)).isoformat())
    whitelisted_sa = make_issue("k3", email=SA_CI, reported=(NOW - timedelta(days=30)).isoformat())
    ops.get_account_open_issues.return_value = [not_reported, too_recent, whitelisted_sa]
    remediator = make_remediator()
    remediator.module_config.in_whitelist.side_effect = lambda account_id, issue_id: issue_id == SA_CI
    remediator.clean_service_account_keys(batch=True)
    client.disable_service_account_key.assert_not_called()
    remediator.jira.add_label.assert_called_once_with(ticket_id=None, label="whitelisted")
    ops.set_status_remediated.assert_not_called()


def test_remediation_skips_already_disabled_or_deleted_key(remediation_env):
    ops, client = remediation_env
    issue = make_issue(reported=(NOW - timedelta(days=30)).isoformat())
    ops.get_account_open_issues.return_value = [issue]
    for key in (None, SimpleNamespace(disabled=True)):
        client.get_service_account_key.return_value = key
        remediator = make_remediator()
        remediator.clean_service_account_keys(batch=True)
    client.disable_service_account_key.assert_not_called()
    ops.set_status_remediated.assert_not_called()


@pytest.mark.parametrize("answer, disabled", [(False, False), (True, True)])
def test_remediation_interactive_confirm(remediation_env, answer, disabled):
    ops, client = remediation_env
    issue = make_issue(reported=(NOW - timedelta(days=30)).isoformat())
    ops.get_account_open_issues.return_value = [issue]
    remediator = make_remediator()
    with mock.patch.object(clean_gcp_sa_keys_rotation, "confirm", return_value=answer) as confirm:
        remediator.clean_service_account_keys(batch=False)
    confirm.assert_called_once()
    assert client.disable_service_account_key.called is disabled
