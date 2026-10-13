"""
Class to remediate GCP bucket public access.
"""
import sys
import logging
import argparse


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.ddb_issues import GCPBucketPublicAccessIssue
from library.gcp.storage import GCPBucketsPublicAccessChecker
from library.multicloud_reporting import MultiCloudIssueRemediator
from library.aws.utility import Account
from library.utility import confirm
from library.utility import SingletonInstance, SingletonInstanceException


class CleanGCPBucketPublicAccess:
    """ Class to remediate GCP bucket public access """
    def __init__(self, config):
        self.config = config
        self.remediator = MultiCloudIssueRemediator(config, config.gcpBucketPublic, GCPBucketPublicAccessIssue)

    def clean_gcp_bucket_public_access(self, batch=False):
        """ Class method to remove public access from GCP buckets which are violating best practices """
        main_account = Account(region=self.config.aws.region)
        backup_bucket = self.config.aws.s3_backup_bucket
        enforce_pap = self.config.gcpBucketPublic.enforce_public_access_prevention

        for account_id, account_name, issue in self.remediator.candidates():
            bucket_name = issue.issue_id
            try:
                account = self.remediator.account(account_id)
                if account.credentials is None:
                    continue

                checker = GCPBucketsPublicAccessChecker(account=account)
                if not checker.check(ids=[bucket_name]):
                    continue
                bucket = checker.get_bucket(bucket_name)
                if bucket is None:
                    logging.debug(f"Bucket {bucket_name} was removed by user")
                elif not bucket.public:
                    logging.debug(f"Bucket {bucket.name} public access issue was remediated by user")
                else:
                    if not batch and \
                       not confirm(f"Do you want to remediate '{bucket_name}' GCP bucket public access", False):
                        continue

                    logging.debug(f"Remediating '{bucket.name}' public access")

                    backup_path = bucket.backup_s3(main_account.client("s3"), backup_bucket)
                    remediation_succeed = True
                    if bucket.restrict(enforce_public_access_prevention=enforce_pap):
                        comment = (f"IAM policy/ACL backup was saved to "
                                   f"[{backup_path}|https://s3.console.aws.amazon.com/s3/object/{backup_bucket}/{backup_path}]. "
                                   f"Bucket '{bucket.name}' public access issue "
                                   f"in '{account_name} / {account_id}' project "
                                   f"was remediated by hammer")
                    else:
                        remediation_succeed = False
                        comment = (f"Failed to remediate bucket '{bucket.name}' public access issue "
                                   f"in '{account_name} / {account_id}' project "
                                   f"due to some limitations. Please, check manually")

                    self.remediator.report_remediation(issue, account_id, account_name,
                                                       comment, succeed=remediation_succeed)
            except Exception:
                logging.exception(f"Error occurred while updating bucket '{bucket_name}' public access "
                                  f"in '{account_name} / {account_id}'")


if __name__ == "__main__":
    module_name = sys.modules[__name__].__loader__.name
    set_logging(level=logging.DEBUG, logfile=f"/var/log/hammer/{module_name}.log")
    config = Config()
    add_cw_logging(config.local.log_group,
                   log_stream=module_name,
                   level=logging.DEBUG,
                   region=config.aws.region)
    try:
        si = SingletonInstance(module_name)
    except SingletonInstanceException:
        logging.error(f"Another instance of '{module_name}' is already running, quitting")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument('--batch', action='store_true', help='Do not ask confirmation for remediation')
    args = parser.parse_args()

    try:
        class_object = CleanGCPBucketPublicAccess(config)
        class_object.clean_gcp_bucket_public_access(batch=args.batch)
    except Exception:
        logging.exception("Failed to clean GCP buckets public access")
