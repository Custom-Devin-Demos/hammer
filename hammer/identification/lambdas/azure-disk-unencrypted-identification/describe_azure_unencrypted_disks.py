import json
import logging


from library.logger import set_logging
from library.config import Config
from library.azure.compute import AzureUnencryptedDisksChecker
from library.azure.utility import AzureAccount
from library.aws.utility import Account
from library.ddb_issues import IssueStatus, AzureUnencryptedDiskIssue
from library.ddb_issues import Operations as IssueOperations
from library.aws.utility import DDB


def lambda_handler(event, context):
    """ Lambda handler to evaluate Azure unencrypted managed disks """
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
        ddb_table = main_account.resource("dynamodb").Table(config.azureDisk.ddb_table_name)

        account = AzureAccount(id=account_id,
                               name=account_name,
                               credentials=config.azure.credentials)
        if account.credential is None:
            return

        logging.debug(f"Checking for Azure unencrypted managed disks in {account}")

        # existing open issues for subscription to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, AzureUnencryptedDiskIssue)
        # make dictionary for fast search by id
        open_issues = {issue.issue_id: issue for issue in open_issues}
        logging.debug(f"Azure unencrypted managed disks in DDB:\n{open_issues.keys()}")

        checker = AzureUnencryptedDisksChecker(
            account=account,
            require_customer_managed_key=config.azureDisk.require_customer_managed_key)
        if checker.check():
            for disk in checker.unencrypted_disks:
                issue = AzureUnencryptedDiskIssue(account_id, disk.id)
                issue.issue_details.provider = account.provider.value
                issue.issue_details.name = disk.name
                issue.issue_details.location = disk.location
                issue.issue_details.resource_group = disk.resource_group
                issue.issue_details.state = disk.state
                issue.issue_details.managed_by = disk.managed_by
                issue.issue_details.sku = disk.sku
                issue.issue_details.size_gb = disk.size_gb
                issue.issue_details.os_type = disk.os_type
                issue.issue_details.encryption_type = disk.encryption_type
                issue.issue_details.disk_encryption_set_id = disk.disk_encryption_set_id
                issue.issue_details.ade_enabled = disk.ade_enabled
                issue.issue_details.tags = disk.tags
                if config.azureDisk.in_whitelist(account_id, disk.id):
                    issue.status = IssueStatus.Whitelisted
                else:
                    issue.status = IssueStatus.Open
                logging.debug(f"Setting {disk.id} status {issue.status}")
                IssueOperations.update(ddb_table, issue)
                # remove issue id from issues_list_from_db (if exists)
                # as we already checked it
                open_issues.pop(disk.id, None)

            logging.debug(f"Azure unencrypted managed disks in DDB:\n{open_issues.keys()}")
            # all other unresolved issues in DDB are for removed/encrypted disks
            for issue in open_issues.values():
                IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check Azure unencrypted managed disks for '{account_id} ({account_name})'")
        return

    logging.debug(f"Checked Azure unencrypted managed disks for '{account_id} ({account_name})'")
