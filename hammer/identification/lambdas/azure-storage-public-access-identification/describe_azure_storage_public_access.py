import json
import logging

from library.logger import set_logging
from library.config import Config
from library.azure.storage import AzureStoragePublicAccessChecker
from library.azure.utility import AzureAccount
from library.aws.utility import Account, DDB
from library.ddb_issues import IssueStatus, AzureStoragePublicAccessIssue
from library.ddb_issues import Operations as IssueOperations


def lambda_handler(event, context):
    """ Lambda handler to evaluate Azure storage accounts public access """
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
        ddb_table = main_account.resource("dynamodb").Table(config.azureStoragePublic.ddb_table_name)

        account = AzureAccount(id=account_id,
                               name=account_name,
                               credentials=config.azure.credentials)
        if account.credential is None:
            return

        logging.debug(f"Checking for public Azure storage accounts in {account}")

        # existing open issues for subscription to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, AzureStoragePublicAccessIssue)
        # make dictionary for fast search by id
        open_issues = {issue.issue_id: issue for issue in open_issues}
        logging.debug(f"Azure storage accounts in DDB:\n{open_issues.keys()}")

        checker = AzureStoragePublicAccessChecker(account=account)
        if not checker.check():
            return

        for storage_account in checker.storage_accounts:
            logging.debug(f"Checking {storage_account.name}")
            if storage_account.public:
                issue = AzureStoragePublicAccessIssue(account_id, storage_account.name)
                issue.issue_details.provider = account.provider.value
                issue.issue_details.name = storage_account.name
                issue.issue_details.location = storage_account.location
                issue.issue_details.resource_group = storage_account.resource_group
                issue.issue_details.resource_id = storage_account.id
                issue.issue_details.public_containers = storage_account.public_containers
                issue.issue_details.tags = storage_account.tags
                if config.azureStoragePublic.in_whitelist(account_id, storage_account.name):
                    issue.status = IssueStatus.Whitelisted
                else:
                    issue.status = IssueStatus.Open
                logging.debug(f"Setting {storage_account.name} status {issue.status}")
                IssueOperations.update(ddb_table, issue)
                # remove issue id from issues_list_from_db (if exists)
                # as we already checked it
                open_issues.pop(storage_account.name, None)

        logging.debug(f"Azure storage accounts in DDB:\n{open_issues.keys()}")
        # all other unresolved issues in DDB are for removed/remediated storage accounts
        for issue in open_issues.values():
            IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check Azure storage accounts public access for '{account_id} ({account_name})'")
        return

    logging.debug(f"Checked Azure storage accounts public access for '{account_id} ({account_name})'")
