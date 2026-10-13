import json
import logging

from library.logger import set_logging
from library.config import Config
from library.cloud import CloudProvider
from library.gcp.storage import GCPBucketsPublicAccessChecker
from library.gcp.utility import GCPAccount
from library.aws.utility import Account, DDB
from library.ddb_issues import IssueStatus, GCPBucketPublicAccessIssue
from library.ddb_issues import Operations as IssueOperations


def lambda_handler(event, context):
    """ Lambda handler to evaluate GCP buckets public access """
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
        ddb_table = main_account.resource("dynamodb").Table(config.gcpBucketPublic.ddb_table_name)

        account = GCPAccount(id=account_id,
                             name=account_name,
                             credentials=config.gcp.credentials)
        if account.credentials is None:
            return

        logging.debug(f"Checking for public GCP buckets in {account}")

        # existing open issues for project to check if resolved
        open_issues = IssueOperations.get_account_open_issues(ddb_table, account_id, GCPBucketPublicAccessIssue)
        # make dictionary for fast search by id
        open_issues = {issue.issue_id: issue for issue in open_issues}
        logging.debug(f"GCP buckets in DDB:\n{open_issues.keys()}")

        checker = GCPBucketsPublicAccessChecker(account=account)
        if not checker.check():
            return

        for bucket in checker.buckets:
            logging.debug(f"Checking {bucket.name}")
            if bucket.public:
                issue = GCPBucketPublicAccessIssue(account_id, bucket.name)
                issue.issue_details.provider = CloudProvider.GCP.value
                issue.issue_details.name = bucket.name
                issue.issue_details.location = bucket.location
                issue.issue_details.tags = bucket.tags
                issue.issue_details.owner = bucket.tags.get("owner", None)
                issue.issue_details.public_bindings = bucket.public_bindings
                issue.issue_details.public_acls = bucket.public_acls
                issue.issue_details.uniform_bucket_level_access = bucket.uniform_access
                issue.issue_details.public_access_prevention = bucket.public_access_prevention
                if config.gcpBucketPublic.in_whitelist(account_id, bucket.name):
                    issue.status = IssueStatus.Whitelisted
                else:
                    issue.status = IssueStatus.Open
                logging.debug(f"Setting {bucket.name} status {issue.status}")
                IssueOperations.update(ddb_table, issue)
                # remove issue id from open issues (if exists)
                # as we already checked it
                open_issues.pop(bucket.name, None)

        # buckets which failed to be evaluated must keep their current status
        for name in checker.failed:
            open_issues.pop(name, None)

        logging.debug(f"GCP buckets in DDB:\n{open_issues.keys()}")
        # all other unresolved issues in DDB are for removed/remediated buckets
        for issue in open_issues.values():
            IssueOperations.set_status_resolved(ddb_table, issue)
        if request_id:
            api_table = main_account.resource("dynamodb").Table(config.api.ddb_table_name)
            DDB.track_progress(api_table, request_id)
    except Exception:
        logging.exception(f"Failed to check GCP buckets public access for '{account_id} ({account_name})'")
        return

    logging.debug(f"Checked GCP buckets public access for '{account_id} ({account_name})'")
