"""
Class to remediate Azure storage accounts public blob access.
"""
import sys
import logging
import argparse


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.ddb_issues import AzureStoragePublicAccessIssue
from library.multicloud_reporting import MultiCloudIssueRemediator
from library.azure.storage import AzureStoragePublicAccessChecker
from library.aws.utility import Account
from library.utility import confirm
from library.utility import SingletonInstance, SingletonInstanceException


class CleanAzureStoragePublicAccess(object):
    """ Class to remediate Azure storage accounts public blob access """
    def __init__(self, config):
        self.config = config
        self.remediator = MultiCloudIssueRemediator(config, config.azureStoragePublic, AzureStoragePublicAccessIssue)

    def clean_azure_storage_public_access(self, batch=False):
        """ Class method to make public blob containers of storage accounts private """
        main_account = Account(region=self.config.aws.region)
        backup_bucket = self.config.aws.s3_backup_bucket

        for account_id, account_name, issue in self.remediator.candidates():
            storage_account_name = issue.issue_id
            title = self.remediator.account_title(account_id, account_name)
            try:
                account = self.remediator.account(account_id)
                if account.credential is None:
                    continue

                checker = AzureStoragePublicAccessChecker(account=account)
                if not checker.check(ids=[storage_account_name]):
                    continue
                storage_account = checker.get_storage_account(storage_account_name)

                if storage_account is None:
                    logging.debug(f"Storage account '{storage_account_name}' was removed by user")
                elif not storage_account.public:
                    logging.debug(f"Storage account '{storage_account_name}' public access issue was remediated by user")
                else:
                    if not batch and \
                       not confirm(f"Do you want to remediate '{storage_account_name}' Azure storage account "
                                   f"public access", False):
                        continue

                    logging.debug(f"Remediating '{storage_account_name}' public access")

                    backup_path = storage_account.backup_s3(main_account.client("s3"), backup_bucket)
                    public_containers = ", ".join(storage_account.public_containers)
                    remediation_succeed = storage_account.restrict(checker.client)
                    if remediation_succeed:
                        comment = (f"Public access state backup was saved to "
                                   f"[{backup_path}|https://s3.console.aws.amazon.com/s3/object/{backup_bucket}/{backup_path}]. "
                                   f"Azure storage account '{storage_account_name}' public access issue "
                                   f"(containers: {public_containers}) in {title} "
                                   f"was remediated by hammer")
                    else:
                        comment = (f"Failed to remediate Azure storage account '{storage_account_name}' "
                                   f"public access issue in {title} "
                                   f"due to some limitations. Please, check manually")

                    self.remediator.report_remediation(issue, account_id, account_name, comment, remediation_succeed)
            except Exception:
                logging.exception(f"Error occurred while updating Azure storage account '{storage_account_name}' "
                                  f"public access in {title}")


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
        class_object = CleanAzureStoragePublicAccess(config)
        class_object.clean_azure_storage_public_access(batch=args.batch)
    except Exception:
        logging.exception("Failed to clean Azure storage accounts public access")
