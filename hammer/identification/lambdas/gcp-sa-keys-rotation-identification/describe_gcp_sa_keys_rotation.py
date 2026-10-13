import json
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.utility import Account, DDB
from library.gcp.utility import GCPAccount
from library.gcp.iam import GCPServiceAccountKeyChecker
from library.ddb_issues import IssueStatus, GCPServiceAccountKeyIssue
from library.ddb_issues import Operations as IssueOperations


def lambda_handler(event, context):
    """ Lambda handler to evaluate GCP service account keys rotation """
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
        ddb_table = main_account.resource("dynamodb").Table(config.gcpServiceAccountKeys.ddb_table_name)

        account = GCPAccount(id=project_id,
                             name=project_name,
                             credentials=config.gcp.credentials)
        if account.credentials is None:
            return

        logging.debug(f"Checking for GCP service account keys rotation for {account}")

        # existing open issues for project to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, project_id, GCPServiceAccountKeyIssue)
        # make dictionary for fast search by id
        open_issues = {issue.issue_id: issue for issue in open_issues}
        logging.debug(f"Service account keys to rotate in DDB:\n{open_issues.keys()}")

        checker = GCPServiceAccountKeyChecker(account=account,
                                              now=config.now,
                                              rotation_criteria_days=config.gcpServiceAccountKeys.rotation_criteria_days)
        if not checker.check():
            return

        for key in checker.stale_keys:
            service_account = key.service_account
            issue = GCPServiceAccountKeyIssue(project_id, key.name)
            issue.issue_details.provider = "gcp"
            issue.issue_details.name = f"{service_account.email}/{key.id}"
            issue.issue_details.location = "global"
            # GCP service accounts do not support labels
            issue.issue_details.tags = {}
            issue.issue_details.service_account = service_account.email
            issue.issue_details.service_account_display_name = service_account.display_name
            issue.issue_details.key_id = key.id
            issue.issue_details.created = key.created.isoformat()
            issue.issue_details.expires = key.expires.isoformat() if key.expires else None
            if config.gcpServiceAccountKeys.in_whitelist(project_id, key.name) or \
               config.gcpServiceAccountKeys.in_whitelist(project_id, service_account.email):
                issue.status = IssueStatus.Whitelisted
            else:
                issue.status = IssueStatus.Open
            logging.debug(f"Setting {key.name} status {issue.status}")
            IssueOperations.update(ddb_table, issue)
            # remove issue id from issues_list_from_db (if exists)
            # as we already checked it
            open_issues.pop(key.name, None)

        logging.debug(f"Service account keys to rotate in DDB:\n{open_issues.keys()}")
        # all other unresolved issues in DDB are for removed/disabled/rotated keys
        for issue in open_issues.values():
            IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check GCP service account keys rotation for '{project_id} ({project_name})'")
        return

    logging.debug(f"Checked GCP service account keys rotation for '{project_id} ({project_name})'")
