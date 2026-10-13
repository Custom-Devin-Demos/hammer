import json
import logging


from library.logger import set_logging
from library.config import Config
from library.gcp.compute import GCPUnencryptedDisksChecker
from library.gcp.utility import GCPAccount
from library.aws.utility import Account
from library.ddb_issues import IssueStatus, GCPUnencryptedDiskIssue
from library.ddb_issues import Operations as IssueOperations
from library.aws.utility import DDB


def lambda_handler(event, context):
    """ Lambda handler to evaluate GCP unencrypted disks """
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
        ddb_table = main_account.resource("dynamodb").Table(config.gcpDisk.ddb_table_name)

        account = GCPAccount(id=project_id,
                             name=project_name,
                             credentials=config.gcp.credentials)
        if account.credentials is None:
            return

        logging.debug(f"Checking for GCP unencrypted disks in {account}")

        # existing open issues for project to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, project_id, GCPUnencryptedDiskIssue)
        # make dictionary for fast search by id
        open_issues = {issue.issue_id: issue for issue in open_issues}
        logging.debug(f"GCP unencrypted disks in DDB:\n{open_issues.keys()}")

        checker = GCPUnencryptedDisksChecker(account=account)
        if checker.check():
            for disk in checker.disks:
                if not disk.encrypted:
                    issue = GCPUnencryptedDiskIssue(project_id, disk.id)
                    issue.issue_details.provider = account.provider.value
                    issue.issue_details.name = disk.name
                    issue.issue_details.location = disk.location
                    issue.issue_details.status = disk.status
                    issue.issue_details.disk_type = disk.type
                    issue.issue_details.size_gb = disk.size_gb
                    issue.issue_details.encryption = disk.encryption
                    issue.issue_details.users = disk.users
                    issue.issue_details.tags = disk.tags
                    if config.gcpDisk.in_whitelist(project_id, disk.id):
                        issue.status = IssueStatus.Whitelisted
                    else:
                        issue.status = IssueStatus.Open
                    logging.debug(f"Setting {disk.id} status {issue.status}")
                    IssueOperations.update(ddb_table, issue)
                    # remove issue id from issues_list_from_db (if exists)
                    # as we already checked it
                    open_issues.pop(disk.id, None)

            logging.debug(f"GCP unencrypted disks in DDB:\n{open_issues.keys()}")
            # all other unresolved issues in DDB are for removed/encrypted disks
            for issue in open_issues.values():
                IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check GCP unencrypted disks for '{project_id} ({project_name})'")
        return

    logging.debug(f"Checked GCP unencrypted disks for '{project_id} ({project_name})'")
