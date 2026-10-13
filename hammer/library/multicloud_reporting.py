"""
Shared reporting / remediation logic for multi-cloud (Azure, GCP) security issues.

`MultiCloudTicketReporter` implements the standard reporting state machine used by every
AWS `reporting/create_*_tickets.py` script:
 * resolved/whitelisted reported issues - close Jira ticket (with `whitelisted` label for whitelisted), notify Slack;
 * reported issues with changed details - comment Jira ticket, notify Slack;
 * not reported issues - create Jira ticket (owner/bu/product from `issue_details.tags`,
   fallback to `ticket_owners.json` is done by `JiraReporting`), notify Slack.

`MultiCloudIssueRemediator` provides common remediation helpers:
iterating remediation candidates (honouring whitelist, fixnow, reported/remediated timestamps and
retention period) and reporting remediation results to Jira/Slack.
"""
import logging


from library.aws.utility import Account
from library.cloud import CloudProvider
from library.jiraoperations import JiraReporting, JiraOperations
from library.slack_utility import SlackNotification
from library.ddb_issues import IssueStatus
from library.ddb_issues import Operations as IssueOperations


PROVIDER_TITLES = {
    CloudProvider.AWS: "AWS",
    CloudProvider.AZURE: "Azure",
    CloudProvider.GCP: "GCP",
}


class MultiCloudBase(object):
    """ Common lazy dependencies (DDB table, Jira, Slack) and helpers for reporter/remediator """
    def __init__(self, config, module_config, issue_class):
        """
        :param config: `library.config.Config` instance
        :param module_config: `library.config.ModuleConfig` instance of the issue type (f.e. `config.azureNsg`)
        :param issue_class: `library.ddb_issues.Issue` child class (f.e. `AzureNSGIssue`)
        """
        self.config = config
        self.module_config = module_config
        self.issue_class = issue_class
        self._ddb_table = None
        self._jira = None
        self._slack = None

    @property
    def ddb_table(self):
        """ :return: boto3 DDB table resource with module issues (in hammer main AWS account) """
        if self._ddb_table is None:
            main_account = Account(region=self.config.aws.region)
            self._ddb_table = main_account.resource("dynamodb").Table(self.module_config.ddb_table_name)
        return self._ddb_table

    @ddb_table.setter
    def ddb_table(self, value):
        self._ddb_table = value

    @property
    def jira(self):
        """ :return: `JiraReporting` instance """
        if self._jira is None:
            self._jira = JiraReporting(self.config)
        return self._jira

    @jira.setter
    def jira(self, value):
        self._jira = value

    @property
    def slack(self):
        """ :return: `SlackNotification` instance """
        if self._slack is None:
            self._slack = SlackNotification(self.config)
        return self._slack

    @slack.setter
    def slack(self, value):
        self._slack = value

    @property
    def provider(self):
        """ :return: `CloudProvider` of the module """
        return self.module_config.provider

    @property
    def provider_title(self):
        """ :return: human readable provider name ("Azure", "GCP") """
        return PROVIDER_TITLES.get(self.provider, str(self.provider))

    @property
    def account_label(self):
        """ :return: name of the provider "account" scope ("account", "subscription", "project") """
        return self.provider.account_label

    def account_title(self, account_id, account_name):
        """ :return: string like "'name / id' subscription" """
        return f"'{account_name} / {account_id}' {self.account_label}"

    def ticket_link(self, issue):
        """ :return: string with Jira ticket url in brackets (or empty string if issue has no ticket) """
        ticket = issue.jira_details.ticket
        return f" ({self.jira.ticket_url(ticket)})" if ticket else ""

    @staticmethod
    def resource_name(issue):
        """ :return: human readable resource name (`issue_details.name`, fallback to `issue_id`) """
        return issue.issue_details.name or issue.issue_id

    @staticmethod
    def reported_owner(issue):
        """ :return: tuple (owner, bu, product) stored in `jira_details` during reporting """
        owner = issue.jira_details.owner
        if owner is None:
            owner = issue.issue_details.owner
        return owner, issue.jira_details.business_unit, issue.jira_details.product


class MultiCloudTicketReporter(MultiCloudBase):
    """
    Base class for Azure/GCP reporting scripts.

    Subclasses usually override `resource_label`, `labels`, `priority`, `recommendation`
    (class attributes or properties) and `issue_description` / `details_table` / `issue_summary` methods.
    Entry point is `create_tickets()`.
    """
    # human readable resource type, used in summary/comments (f.e. "Azure NSG")
    resource_label = "resource"
    # Jira ticket labels (defaults to [module section name])
    labels = None
    # Jira ticket priority
    priority = "Major"
    # recommendation text appended to Jira ticket description
    recommendation = ""

    def issue_summary(self, issue, account_id, account_name):
        """
        :return: Jira ticket summary (without BU suffix, it is appended automatically)
        """
        return (f"{self.resource_label} '{self.resource_name(issue)}' security issue "
                f"in {self.account_title(account_id, account_name)}")

    def issue_description(self, issue, account_id, account_name):
        """
        :return: Jira ticket description header - issue explanation, threat and risk.
                 Account/resource details, auto-remediation date, tags, `details_table` and recommendation
                 are appended automatically.
        """
        return f"{self.resource_label} has a security issue.\n\n"

    def details_table(self, issue):
        """
        :return: Jira markup with issue specific details (f.e. table with offending rules).
                 Used in new ticket description and in update comment.
        """
        return ""

    def get_labels(self):
        """ :return: list with Jira labels """
        return list(self.labels) if self.labels else [self.module_config.name]

    def owner_from_tags(self, issue):
        """
        :return: tuple (owner, bu, product) based on resource tags/labels
                 (bu falls back to guessing from resource name)
        """
        tags = issue.issue_details.tags or {}
        owner = tags.get("owner", None)
        bu = tags.get("bu", None)
        product = tags.get("product", None)
        if bu is None:
            bu = self.config.get_bu_by_name(self.resource_name(issue))
        return owner, bu, product

    def common_details(self, issue, account_id, account_name, owner):
        """ :return: Jira markup with provider/account/resource details """
        label = self.account_label.capitalize()
        desc = (f"*Cloud Provider*: {self.provider_title}\n"
                f"*{label} Name*: {account_name}\n"
                f"*{label} ID*: {account_id}\n"
                f"*{self.resource_label}*: {self.resource_name(issue)}\n")
        if issue.issue_details.location:
            desc += f"*Location*: {issue.issue_details.location}\n"
        if issue.issue_details.resource_group:
            desc += f"*Resource Group*: {issue.issue_details.resource_group}\n"
        desc += f"*Owner*: {owner}\n\n"
        return desc

    def build_description(self, issue, account_id, account_name, owner):
        """ :return: full Jira ticket description """
        tags = issue.issue_details.tags or {}
        desc = self.issue_description(issue, account_id, account_name)
        desc += self.common_details(issue, account_id, account_name, owner)
        if self.module_config.remediation:
            auto_remediation_date = (self.config.now + self.module_config.issue_retention_date).date()
            desc += f"\n{{color:red}}*Auto-Remediation Date*: {auto_remediation_date}{{color}}\n\n"
        desc += JiraOperations.build_tags_table(tags)
        desc += self.details_table(issue)
        desc += "\n"
        if self.recommendation:
            desc += f"*Recommendation*: {self.recommendation} "
        if self.config.whitelisting_procedure_url:
            desc += (f"For any other exceptions, please follow the "
                     f"[whitelisting procedure|{self.config.whitelisting_procedure_url}] "
                     f"and provide a strong business reasoning. ")
        return desc

    def close_issue(self, issue, account_id, account_name):
        """ Close Jira ticket of resolved/whitelisted issue and mark issue as closed """
        owner, bu, product = self.reported_owner(issue)
        name = self.resource_name(issue)
        logging.debug(f"Closing {issue.status.value} {self.resource_label} '{name}' issue")

        comment = (f"Closing {issue.status.value} {self.resource_label} '{name}' issue "
                   f"in {self.account_title(account_id, account_name)}")
        if issue.status == IssueStatus.Whitelisted:
            # Adding label with "whitelisted" to jira ticket.
            self.jira.add_label(
                ticket_id=issue.jira_details.ticket,
                label=IssueStatus.Whitelisted.value
            )
        self.jira.close_issue(
            ticket_id=issue.jira_details.ticket,
            comment=comment
        )
        self.slack.report_issue(
            msg=f"{comment}{self.ticket_link(issue)}",
            owner=owner,
            account_id=account_id,
            bu=bu, product=product,
        )
        IssueOperations.set_status_closed(self.ddb_table, issue)

    def update_issue(self, issue, account_id, account_name):
        """ Comment Jira ticket of issue with changed details """
        owner, bu, product = self.reported_owner(issue)
        name = self.resource_name(issue)
        logging.debug(f"Updating {self.resource_label} '{name}' issue")

        comment = "Issue details are changed, please check again.\n"
        comment += self.details_table(issue)
        comment += JiraOperations.build_tags_table(issue.issue_details.tags or {})
        self.jira.update_issue(
            ticket_id=issue.jira_details.ticket,
            comment=comment
        )
        self.slack.report_issue(
            msg=f"{self.resource_label} '{name}' issue is changed "
                f"in {self.account_title(account_id, account_name)}{self.ticket_link(issue)}",
            owner=owner,
            account_id=account_id,
            bu=bu, product=product,
        )
        IssueOperations.set_status_updated(self.ddb_table, issue)

    def report_issue(self, issue, account_id, account_name):
        """
        Create Jira ticket for new issue and notify Slack.

        :return: boolean, if issue was reported
        """
        name = self.resource_name(issue)
        logging.debug(f"Reporting {self.resource_label} '{name}' issue")

        owner, bu, product = self.owner_from_tags(issue)

        issue_summary = self.issue_summary(issue, account_id, account_name)
        if bu:
            issue_summary += f" [{bu}]"
        issue_description = self.build_description(issue, account_id, account_name, owner)

        try:
            response = self.jira.add_issue(
                issue_summary=issue_summary, issue_description=issue_description,
                priority=self.priority, labels=self.get_labels(),
                owner=owner,
                account_id=account_id,
                bu=bu, product=product,
            )
        except Exception:
            logging.exception("Failed to create jira ticket")
            return False

        if response is not None:
            issue.jira_details.ticket = response.ticket_id
            issue.jira_details.ticket_assignee_id = response.ticket_assignee_id

        issue.jira_details.owner = owner
        issue.jira_details.business_unit = bu
        issue.jira_details.product = product

        self.slack.report_issue(
            msg=f"Discovered {issue_summary}{self.ticket_link(issue)}",
            owner=owner,
            account_id=account_id,
            bu=bu, product=product,
        )

        IssueOperations.set_status_reported(self.ddb_table, issue)
        return True

    def process_issue(self, issue, account_id, account_name):
        """ Apply reporting state machine to one not closed issue """
        if issue.timestamps.reported is not None:
            if issue.status in [IssueStatus.Resolved, IssueStatus.Whitelisted]:
                self.close_issue(issue, account_id, account_name)
            # issue.status != IssueStatus.Closed (should be IssueStatus.Open)
            elif issue.timestamps.updated > issue.timestamps.reported:
                self.update_issue(issue, account_id, account_name)
            else:
                logging.debug(f"No changes for '{self.resource_name(issue)}'")
        # issue has not been reported yet
        else:
            self.report_issue(issue, account_id, account_name)

    def create_tickets(self):
        """ Report all not closed module issues in all module accounts """
        for account_id, account_name in self.module_config.accounts.items():
            logging.debug(f"Checking {self.account_title(account_id, account_name)}")
            issues = IssueOperations.get_account_not_closed_issues(self.ddb_table, account_id, self.issue_class)
            for issue in issues:
                try:
                    self.process_issue(issue, account_id, account_name)
                except Exception:
                    logging.exception(f"Failed to report '{issue.issue_id}' issue "
                                      f"in {self.account_title(account_id, account_name)}")


class MultiCloudIssueRemediator(MultiCloudBase):
    """
    Helper for Azure/GCP remediation scripts:

        remediator = MultiCloudIssueRemediator(config, config.azureNsg, AzureNSGIssue)
        for account_id, account_name, issue in remediator.candidates():
            account = remediator.account(account_id)
            ... check issue still exists, ask confirmation unless batch, backup, remediate ...
            remediator.report_remediation(issue, account_id, account_name, comment, succeed)
    """
    def account(self, account_id):
        """ :return: `AzureAccount` / `GCPAccount` for module provider with name and credentials from config """
        if self.provider == CloudProvider.AZURE:
            from library.azure.utility import AzureAccount
            return AzureAccount.from_config(self.config, account_id)
        if self.provider == CloudProvider.GCP:
            from library.gcp.utility import GCPAccount
            return GCPAccount.from_config(self.config, account_id)
        raise ValueError(f"Unsupported provider '{self.provider}' for multi-cloud remediation")

    def candidates(self):
        """
        Iterate over open issues in module `remediation_accounts` which should be remediated:
        not whitelisted (whitelisted issues get `whitelisted` Jira label), already reported,
        not remediated yet and reported at least `remediation_retention_period` days ago.

        :return: generator of tuples (account_id, account_name, issue)
        """
        retention_period = self.module_config.remediation_retention_period
        for account_id, account_name in self.module_config.remediation_accounts.items():
            logging.debug(f"Checking {self.account_title(account_id, account_name)}")
            issues = IssueOperations.get_account_open_issues(self.ddb_table, account_id, self.issue_class)
            for issue in issues:
                issue_id = issue.issue_id
                if self.module_config.in_whitelist(account_id, issue_id):
                    logging.debug(f"Skipping {issue_id} (in whitelist)")
                    # Adding label with "whitelisted" to jira ticket.
                    self.jira.add_label(
                        ticket_id=issue.jira_details.ticket,
                        label=IssueStatus.Whitelisted.value
                    )
                    continue

                if issue.timestamps.reported is None:
                    logging.debug(f"Skipping '{issue_id}' (was not reported)")
                    continue

                if issue.timestamps.remediated is not None:
                    logging.debug(f"Skipping {issue_id} (has been already remediated)")
                    continue

                no_of_days_issue_created = (self.config.now - issue.timestamp_as_datetime).days
                if no_of_days_issue_created < retention_period and \
                   not self.module_config.in_fixnow(account_id, issue_id):
                    logging.debug(f"Skipping '{issue_id}' "
                                  f"({retention_period - no_of_days_issue_created} days before remediation)")
                    continue

                yield account_id, account_name, issue

    def report_remediation(self, issue, account_id, account_name, comment, succeed=True):
        """
        Comment Jira ticket (reassign to hammer user on success), notify Slack
        and update issue remediated timestamp.
        """
        owner, bu, product = self.reported_owner(issue)
        self.jira.remediate_issue(
            ticket_id=issue.jira_details.ticket,
            comment=comment,
            reassign=succeed,
        )
        self.slack.report_issue(
            msg=f"{comment}{self.ticket_link(issue)}",
            owner=owner,
            account_id=account_id,
            bu=bu, product=product,
        )
        IssueOperations.set_status_remediated(self.ddb_table, issue)
