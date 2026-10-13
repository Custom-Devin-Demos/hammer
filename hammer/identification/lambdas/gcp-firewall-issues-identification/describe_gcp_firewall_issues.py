import json
import logging


from library.logger import set_logging
from library.config import Config
from library.gcp.firewall import FirewallChecker
from library.gcp.utility import GCPAccount
from library.aws.utility import Account
from library.ddb_issues import IssueStatus, GCPFirewallIssue
from library.ddb_issues import Operations as IssueOperations
from library.aws.utility import DDB


def lambda_handler(event, context):
    """ Lambda handler to evaluate GCP firewall rules unrestricted access """
    set_logging(level=logging.INFO)

    try:
        payload = json.loads(event["Records"][0]["Sns"]["Message"])
        project_id = payload['account_id']
        project_name = payload['account_name']
        # if request_id is present in payload then this lambda was called from the API
        request_id = payload.get('request_id', None)
    except Exception:
        logging.exception(f"Failed to parse event\n{event}")
        return

    try:
        config = Config()

        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(config.gcpFirewall.ddb_table_name)

        account = GCPAccount(id=project_id,
                             name=project_name,
                             credentials=config.gcp.credentials)
        if account.credentials is None:
            return

        logging.debug(f"Checking for GCP firewall rules unrestricted access in {account}")

        # existing open issues for project to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, project_id, GCPFirewallIssue)
        # make dictionary for fast search by id
        open_issues = {issue.issue_id: issue for issue in open_issues}
        logging.debug(f"GCP firewall rules in DDB:\n{open_issues.keys()}")

        checker = FirewallChecker(account=account,
                                  restricted_ports=config.gcpFirewall.restricted_ports)
        if checker.check():
            for rule in checker.rules:
                logging.debug(f"Checking {rule.name}")
                if not rule.restricted:
                    issue = GCPFirewallIssue(project_id, rule.name)
                    issue.issue_details.provider = config.gcpFirewall.provider.value
                    issue.issue_details.name = rule.name
                    # VPC firewall rules are global resources
                    issue.issue_details.location = "global"
                    issue.issue_details.tags = rule.tags
                    issue.issue_details.network = rule.network
                    issue.issue_details.priority = rule.priority
                    issue.issue_details.rules = rule.rules
                    issue.issue_details.target_tags = rule.target_tags
                    issue.issue_details.target_service_accounts = rule.target_service_accounts
                    if config.gcpFirewall.in_whitelist(project_id, rule.name):
                        issue.status = IssueStatus.Whitelisted
                    else:
                        issue.status = IssueStatus.Open
                    logging.debug(f"Setting {rule.name} status {issue.status}")
                    IssueOperations.update(ddb_table, issue)
                    # remove issue id from issues_list_from_db (if exists)
                    # as we already checked it
                    open_issues.pop(rule.name, None)

            logging.debug(f"GCP firewall rules in DDB:\n{open_issues.keys()}")
            # all other unresolved issues in DDB are for removed/remediated firewall rules
            for issue in open_issues.values():
                IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check GCP firewall rules for '{project_id} ({project_name})'")
        return

    logging.debug(f"Checked GCP firewall rules for '{project_id} ({project_name})'")
