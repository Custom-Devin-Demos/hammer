import os
import sys
import pytest


from datetime import datetime, timedelta, timezone
from unittest import mock
from library.cloud import CloudProvider
from library.ddb_issues import IssueStatus, AzureNSGIssue, GCPFirewallIssue
from library import multicloud_reporting
from library.multicloud_reporting import MultiCloudTicketReporter, MultiCloudIssueRemediator
from library.jiraoperations import NewIssue


ACCOUNT_ID = "00000000-0000-0000-0000-000000000001"
ACCOUNT_NAME = "azure-prod"


class NSGReporter(MultiCloudTicketReporter):
    resource_label = "Azure NSG"
    labels = ["azure-nsg"]
    priority = "Critical"
    recommendation = "Restrict NSG inbound rules."

    def issue_summary(self, issue, account_id, account_name):
        return f"Azure NSG '{self.resource_name(issue)}' with unrestricted access in '{account_name} / {account_id}'"

    def issue_description(self, issue, account_id, account_name):
        return "NSG allows unrestricted inbound access.\n\n*Risk*: High\n\n"

    def details_table(self, issue):
        return "".join(f"|{rule['name']}|{rule['ports']}|\n" for rule in issue.issue_details.rules or [])


def make_module_config(provider=CloudProvider.AZURE, remediation=False, accounts=None, retention=0):
    module = mock.Mock()
    module.provider = provider
    module.name = "azure_nsg_unrestricted_access"
    module.accounts = accounts if accounts is not None else {ACCOUNT_ID: ACCOUNT_NAME}
    module.remediation_accounts = module.accounts
    module.remediation = remediation
    module.issue_retention_date = timedelta(days=retention)
    module.remediation_retention_period = retention
    module.in_whitelist.return_value = False
    module.in_fixnow.return_value = False
    return module


def make_config():
    config = mock.Mock()
    config.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    config.whitelisting_procedure_url = "https://wiki/whitelist"
    config.get_bu_by_name.return_value = None
    return config


def make_issue(issue_id="/subscriptions/x/nsg-1", status=IssueStatus.Open, reported=None, updated=None,
               tags=None, issue_class=AzureNSGIssue):
    issue = issue_class(ACCOUNT_ID, issue_id)
    issue.status = status
    issue.issue_details.name = "nsg-1"
    issue.issue_details.location = "westeurope"
    issue.issue_details.resource_group = "rg-1"
    issue.issue_details.provider = "azure"
    issue.issue_details.tags = tags if tags is not None else {"owner": "alice", "bu": "news", "product": "web"}
    issue.issue_details.rules = [{"name": "allow-ssh", "ports": "22"}]
    issue.timestamps.reported = reported
    if updated is not None:
        issue.timestamps.updated = updated
    return issue


@pytest.fixture
def ops():
    with mock.patch.object(multicloud_reporting, "IssueOperations") as operations:
        yield operations


def make_reporter(issues, ops, module_config=None, config=None):
    reporter = NSGReporter(config or make_config(), module_config or make_module_config(), AzureNSGIssue)
    reporter.ddb_table = mock.Mock(name="ddb_table")
    reporter.jira = mock.Mock(name="jira")
    reporter.jira.ticket_url.side_effect = lambda ticket: f"https://jira/{ticket}"
    reporter.slack = mock.Mock(name="slack")
    ops.get_account_not_closed_issues.return_value = issues
    return reporter


def test_report_new_issue(ops):
    issue = make_issue()
    reporter = make_reporter([issue], ops)
    reporter.jira.add_issue.return_value = NewIssue(ticket_id="SEC-1", ticket_assignee_id="alice")

    reporter.create_tickets()

    ops.get_account_not_closed_issues.assert_called_once_with(reporter.ddb_table, ACCOUNT_ID, AzureNSGIssue)
    kwargs = reporter.jira.add_issue.call_args[1]
    assert kwargs["issue_summary"] == f"Azure NSG 'nsg-1' with unrestricted access in '{ACCOUNT_NAME} / {ACCOUNT_ID}' [news]"
    assert kwargs["priority"] == "Critical"
    assert kwargs["labels"] == ["azure-nsg"]
    assert (kwargs["owner"], kwargs["bu"], kwargs["product"], kwargs["account_id"]) == ("alice", "news", "web", ACCOUNT_ID)
    description = kwargs["issue_description"]
    assert description.startswith("NSG allows unrestricted inbound access.")
    assert "*Cloud Provider*: Azure" in description
    assert f"*Subscription ID*: {ACCOUNT_ID}" in description
    assert "*Location*: westeurope" in description
    assert "*Resource Group*: rg-1" in description
    assert "|allow-ssh|22|" in description
    assert "*Recommendation*: Restrict NSG inbound rules." in description
    assert "whitelisting procedure|https://wiki/whitelist" in description
    # remediation disabled - no auto-remediation date
    assert "Auto-Remediation Date" not in description

    assert issue.jira_details.ticket == "SEC-1"
    assert issue.jira_details.ticket_assignee_id == "alice"
    assert (issue.jira_details.owner, issue.jira_details.business_unit, issue.jira_details.product) == \
           ("alice", "news", "web")
    msg = reporter.slack.report_issue.call_args[1]["msg"]
    assert msg.startswith("Discovered Azure NSG 'nsg-1'") and msg.endswith("(https://jira/SEC-1)")
    ops.set_status_reported.assert_called_once_with(reporter.ddb_table, issue)


def test_report_new_issue_defaults_and_bu_fallback(ops):
    issue = make_issue(tags={})
    config = make_config()
    config.get_bu_by_name.return_value = "finance"
    module_config = make_module_config(remediation=True, retention=21)
    reporter = MultiCloudTicketReporter(config, module_config, AzureNSGIssue)
    reporter.ddb_table = mock.Mock()
    reporter.jira = mock.Mock()
    reporter.slack = mock.Mock()
    reporter.jira.add_issue.return_value = None
    ops.get_account_not_closed_issues.return_value = [issue]

    reporter.create_tickets()

    kwargs = reporter.jira.add_issue.call_args[1]
    assert kwargs["labels"] == ["azure_nsg_unrestricted_access"]
    assert kwargs["priority"] == "Major"
    assert (kwargs["owner"], kwargs["bu"], kwargs["product"]) == (None, "finance", None)
    assert kwargs["issue_summary"].endswith(f"in '{ACCOUNT_NAME} / {ACCOUNT_ID}' subscription [finance]")
    assert "*Auto-Remediation Date*: 2026-01-22" in kwargs["issue_description"]
    assert issue.jira_details.ticket is None
    ops.set_status_reported.assert_called_once_with(reporter.ddb_table, issue)


def test_jira_failure_does_not_mark_reported(ops):
    issue = make_issue()
    reporter = make_reporter([issue], ops)
    reporter.jira.add_issue.side_effect = Exception("jira is down")
    reporter.create_tickets()
    ops.set_status_reported.assert_not_called()
    reporter.slack.report_issue.assert_not_called()


@pytest.mark.parametrize("status", [IssueStatus.Resolved, IssueStatus.Whitelisted])
def test_close_resolved_or_whitelisted(ops, status):
    issue = make_issue(status=status, reported="2025-01-01T00:00:00+00:00", updated="2025-01-01T00:00:00+00:00")
    issue.jira_details.ticket = "SEC-2"
    issue.jira_details.owner = "bob"
    issue.jira_details.business_unit = "news"
    issue.jira_details.product = "web"
    reporter = make_reporter([issue], ops)

    reporter.create_tickets()

    if status == IssueStatus.Whitelisted:
        reporter.jira.add_label.assert_called_once_with(ticket_id="SEC-2", label="whitelisted")
    else:
        reporter.jira.add_label.assert_not_called()
    comment = reporter.jira.close_issue.call_args[1]["comment"]
    assert comment == (f"Closing {status.value} Azure NSG 'nsg-1' issue "
                       f"in '{ACCOUNT_NAME} / {ACCOUNT_ID}' subscription")
    slack_kwargs = reporter.slack.report_issue.call_args[1]
    assert slack_kwargs["msg"] == f"{comment} (https://jira/SEC-2)"
    assert (slack_kwargs["owner"], slack_kwargs["bu"], slack_kwargs["product"]) == ("bob", "news", "web")
    ops.set_status_closed.assert_called_once_with(reporter.ddb_table, issue)
    reporter.jira.add_issue.assert_not_called()


def test_update_changed_issue(ops):
    issue = make_issue(reported="2025-01-01T00:00:00+00:00", updated="2025-02-01T00:00:00+00:00")
    issue.jira_details.ticket = "SEC-3"
    reporter = make_reporter([issue], ops)

    reporter.create_tickets()

    comment = reporter.jira.update_issue.call_args[1]["comment"]
    assert comment.startswith("Issue details are changed, please check again.\n")
    assert "|allow-ssh|22|" in comment
    assert reporter.slack.report_issue.call_args[1]["msg"] == (
        f"Azure NSG 'nsg-1' issue is changed in '{ACCOUNT_NAME} / {ACCOUNT_ID}' subscription (https://jira/SEC-3)")
    ops.set_status_updated.assert_called_once_with(reporter.ddb_table, issue)


def test_no_changes(ops):
    issue = make_issue(reported="2025-02-01T00:00:00+00:00", updated="2025-01-01T00:00:00+00:00")
    reporter = make_reporter([issue], ops)
    reporter.create_tickets()
    for method in ("add_issue", "update_issue", "close_issue"):
        getattr(reporter.jira, method).assert_not_called()
    reporter.slack.report_issue.assert_not_called()
    for method in ("set_status_reported", "set_status_updated", "set_status_closed"):
        getattr(ops, method).assert_not_called()


def test_gcp_account_label(ops):
    issue = make_issue(issue_class=GCPFirewallIssue, tags={})
    module_config = make_module_config(provider=CloudProvider.GCP, accounts={"proj-1": "gcp-prod"})
    reporter = make_reporter([issue], ops, module_config=module_config)
    reporter.create_tickets()
    description = reporter.jira.add_issue.call_args[1]["issue_description"]
    assert "*Cloud Provider*: GCP" in description
    assert "*Project ID*: proj-1" in description


def test_default_ddb_table_uses_main_account(ops):
    config = make_config()
    config.aws.region = "eu-west-1"
    module_config = make_module_config()
    module_config.ddb_table_name = "hammer-azure-nsg-unrestricted"
    reporter = MultiCloudTicketReporter(config, module_config, AzureNSGIssue)
    with mock.patch.object(multicloud_reporting, "Account") as account:
        table = reporter.ddb_table
        account.assert_called_once_with(region="eu-west-1")
        account.return_value.resource.assert_called_once_with("dynamodb")
        account.return_value.resource.return_value.Table.assert_called_once_with("hammer-azure-nsg-unrestricted")
        assert reporter.ddb_table is table


def make_remediator(issues, ops, module_config=None):
    config = make_config()
    remediator = MultiCloudIssueRemediator(config, module_config or make_module_config(retention=10), AzureNSGIssue)
    remediator.ddb_table = mock.Mock()
    remediator.jira = mock.Mock()
    remediator.jira.ticket_url.side_effect = lambda ticket: f"https://jira/{ticket}"
    remediator.slack = mock.Mock()
    ops.get_account_open_issues.return_value = issues
    return remediator


def test_remediation_candidates(ops):
    old = "2025-12-01T00:00:00+00:00"
    recent = "2025-12-30T00:00:00+00:00"
    ready = make_issue("ready", reported=old)
    whitelisted = make_issue("whitelisted", reported=old)
    whitelisted.jira_details.ticket = "SEC-9"
    not_reported = make_issue("not-reported")
    remediated = make_issue("remediated", reported=old)
    remediated.timestamps.remediated = old
    too_recent = make_issue("too-recent", reported=recent)
    fixnow = make_issue("fixnow", reported=recent)

    module_config = make_module_config(retention=10)
    module_config.in_whitelist.side_effect = lambda account_id, issue_id: issue_id == "whitelisted"
    module_config.in_fixnow.side_effect = lambda account_id, issue_id: issue_id == "fixnow"
    remediator = make_remediator([ready, whitelisted, not_reported, remediated, too_recent, fixnow], ops,
                                 module_config=module_config)

    candidates = list(remediator.candidates())

    assert [issue.issue_id for _, _, issue in candidates] == ["ready", "fixnow"]
    assert all((account_id, account_name) == (ACCOUNT_ID, ACCOUNT_NAME) for account_id, account_name, _ in candidates)
    remediator.jira.add_label.assert_called_once_with(ticket_id="SEC-9", label="whitelisted")
    ops.get_account_open_issues.assert_called_once_with(remediator.ddb_table, ACCOUNT_ID, AzureNSGIssue)


@pytest.mark.parametrize("succeed", [True, False])
def test_report_remediation(ops, succeed):
    issue = make_issue(reported="2025-12-01T00:00:00+00:00")
    issue.jira_details.ticket = "SEC-5"
    issue.jira_details.owner = "alice"
    remediator = make_remediator([issue], ops)
    remediator.report_remediation(issue, ACCOUNT_ID, ACCOUNT_NAME, "remediated by hammer", succeed)
    remediator.jira.remediate_issue.assert_called_once_with(ticket_id="SEC-5", comment="remediated by hammer",
                                                            reassign=succeed)
    assert remediator.slack.report_issue.call_args[1]["msg"] == "remediated by hammer (https://jira/SEC-5)"
    ops.set_status_remediated.assert_called_once_with(remediator.ddb_table, issue)


def test_remediator_account_factory(ops):
    remediator = make_remediator([], ops)
    remediator.config.azure.accounts = {ACCOUNT_ID: ACCOUNT_NAME}
    remediator.config.azure.credentials = {"tenant_id": "t"}
    account = remediator.account(ACCOUNT_ID)
    assert account.provider is CloudProvider.AZURE and account.name == ACCOUNT_NAME

    remediator.module_config.provider = CloudProvider.GCP
    remediator.config.gcp.accounts = {"proj": "gcp-prod"}
    remediator.config.gcp.credentials = {}
    account = remediator.account("proj")
    assert account.provider is CloudProvider.GCP and account.name == "gcp-prod"

    remediator.module_config.provider = CloudProvider.AWS
    with pytest.raises(ValueError):
        remediator.account("123")


def test_scheduler_registers_multicloud_modules(tmp_path):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "hammer", "reporting-remediation"))
    try:
        from cronjobs import automation_scheduler
    finally:
        sys.path.pop(0)

    def module(reporting, remediation):
        return mock.Mock(reporting=reporting, remediation=remediation)

    config = mock.Mock()
    config.cronjobs = {"reporting": "55 * * * *", "remediation": "45 10 * * *", "python": "python3.9"}
    config.csv.enabled = True
    config.csv.schedule = "0 9 * * 1"
    for attr in ("s3acl", "sg", "iamUserInactiveKeys", "iamUserKeysRotation", "s3policy", "cloudtrails",
                 "ebsVolume", "ebsSnapshot", "rdsSnapshot", "publicAMIs", "sqspolicy", "s3Encrypt", "rdsEncrypt"):
        setattr(config, attr, module(False, False))
    for attr in ("azureStoragePublic", "azureNsg", "azureDisk", "azureStorageKeys",
                 "gcpBucketPublic", "gcpFirewall", "gcpDisk", "gcpServiceAccountKeys"):
        setattr(config, attr, module(True, True))

    with mock.patch.object(automation_scheduler.CronJobs, "save", autospec=True) as save:
        automation_scheduler.automation_cronjob(config)
    jobs = {job.title: job.jobs for job in (call[0][0] for call in save.call_args_list)}

    reporting = "\n".join(jobs["hammer-reporting"])
    remediation = "\n".join(jobs["hammer-remediation"])
    assert "python3.9 -m analytics.security_issues_csv_report" in reporting
    assert "python3.6" not in reporting + remediation
    for script in ("create_azure_storage_public_access_issue_tickets", "create_azure_nsg_issue_tickets",
                   "create_azure_unencrypted_disk_issue_tickets", "create_azure_storage_keys_rotation_issue_tickets",
                   "create_gcp_bucket_public_access_issue_tickets", "create_gcp_firewall_issue_tickets",
                   "create_gcp_unencrypted_disk_issue_tickets", "create_gcp_sa_keys_rotation_issue_tickets"):
        assert f"python3.9 -m reporting.{script}\n" in reporting + "\n"
    for script in ("clean_azure_storage_public_access", "clean_azure_nsg_issues", "clean_azure_storage_keys_rotation",
                   "clean_gcp_bucket_public_access", "clean_gcp_firewall_issues", "clean_gcp_sa_keys_rotation"):
        assert f"python3.9 -m remediation.{script} --batch" in remediation
    assert len(jobs["hammer-remediation"]) == 6
    assert len(jobs["hammer-reporting"]) == 9


def test_scheduler_default_python():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "hammer", "reporting-remediation"))
    try:
        from cronjobs import automation_scheduler
    finally:
        sys.path.pop(0)
    config = mock.MagicMock()
    config.cronjobs = {"reporting": "55 * * * *", "remediation": "45 10 * * *"}
    config.csv.enabled = True
    with mock.patch.object(automation_scheduler.CronJobs, "save", autospec=True) as save:
        automation_scheduler.automation_cronjob(config)
    reporting = [call[0][0] for call in save.call_args_list if call[0][0].title == "hammer-reporting"][0]
    assert all("python3.6 -m" in job for job in reporting.jobs)
