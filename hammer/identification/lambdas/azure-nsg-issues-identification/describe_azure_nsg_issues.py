import json
import logging


from library.logger import set_logging
from library.config import Config
from library.azure.network import AzureNSGChecker
from library.azure.utility import AzureAccount
from library.aws.utility import Account
from library.ddb_issues import IssueStatus, AzureNSGIssue
from library.ddb_issues import Operations as IssueOperations
from library.aws.utility import DDB


def lambda_handler(event, context):
    """ Lambda handler to evaluate Azure network security groups unrestricted access """
    set_logging(level=logging.INFO)

    try:
        payload = json.loads(event["Records"][0]["Sns"]["Message"])
        account_id = payload['account_id']
        account_name = payload['account_name']
        # if request_id is present in payload then this lambda was called from the API
        request_id = payload.get('request_id', None)
    except Exception:
        logging.exception(f"Failed to parse event\n{event}")
        return

    try:
        config = Config()

        main_account = Account(region=config.aws.region)
        ddb_table = main_account.resource("dynamodb").Table(config.azureNsg.ddb_table_name)

        account = AzureAccount(id=account_id,
                               name=account_name,
                               credentials=config.azure.credentials)
        if account.credential is None:
            return

        logging.debug(f"Checking for Azure NSG unrestricted access in {account}")

        # existing open issues for subscription to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, AzureNSGIssue)
        # make dictionary for fast search by id
        open_issues = {issue.issue_id: issue for issue in open_issues}
        logging.debug(f"Azure NSGs in DDB:\n{open_issues.keys()}")

        checker = AzureNSGChecker(account=account,
                                  restricted_ports=config.azureNsg.restricted_ports)
        if checker.check():
            for nsg in checker.groups:
                logging.debug(f"Checking {nsg.name} ({nsg.id})")
                if not nsg.restricted:
                    issue = AzureNSGIssue(account_id, nsg.id)
                    issue.issue_details.provider = "azure"
                    issue.issue_details.name = nsg.name
                    issue.issue_details.location = nsg.location
                    issue.issue_details.resource_group = nsg.resource_group
                    issue.issue_details.tags = nsg.tags
                    issue.issue_details.rules = [rule.as_issue_rule() for rule in nsg.open_rules]
                    issue.issue_details.network_interfaces = nsg.network_interfaces
                    issue.issue_details.subnets = nsg.subnets
                    if config.azureNsg.in_whitelist(account_id, nsg.id):
                        issue.status = IssueStatus.Whitelisted
                    else:
                        issue.status = IssueStatus.Open
                    logging.debug(f"Setting {nsg.id} status {issue.status}")
                    IssueOperations.update(ddb_table, issue)
                    # remove issue id from issues_list_from_db (if exists)
                    # as we already checked it
                    open_issues.pop(nsg.id, None)

            logging.debug(f"Azure NSGs in DDB:\n{open_issues.keys()}")
            # all other unresolved issues in DDB are for removed/remediated NSGs
            for issue in open_issues.values():
                IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check Azure NSG unrestricted access for '{account_id} ({account_name})'")
        return

    logging.debug(f"Checked Azure NSG unrestricted access for '{account_id} ({account_name})'")
