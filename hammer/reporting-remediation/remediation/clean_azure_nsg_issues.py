"""
Class to remediate Azure network security groups unrestricted access issues.
"""
import sys
import logging
import argparse


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.azure.network import AzureNSGChecker
from library.aws.utility import Account
from library.ddb_issues import AzureNSGIssue
from library.multicloud_reporting import MultiCloudIssueRemediator
from library.utility import confirm
from library.utility import SingletonInstance, SingletonInstanceException


class CleanAzureNSGIssues(object):
    """ Class to restrict Azure NSG rules with unrestricted inbound access """
    def __init__(self, config):
        self.config = config
        self.remediator = MultiCloudIssueRemediator(config, config.azureNsg, AzureNSGIssue)

    def clean_azure_nsg_issues(self, batch=False):
        """ Class function to restrict Azure NSG rules which allow world-wide access to restricted ports """
        main_account = Account(region=self.config.aws.region)
        backup_bucket = self.config.aws.s3_backup_bucket

        for account_id, account_name, issue in self.remediator.candidates():
            nsg_id = issue.issue_id
            nsg_name = issue.issue_details.name
            try:
                account = self.remediator.account(account_id)
                if account.credential is None:
                    continue

                checker = AzureNSGChecker(account=account,
                                          restricted_ports=self.config.azureNsg.restricted_ports)
                if not checker.check(ids=[nsg_id]):
                    continue
                nsg = checker.get_nsg(nsg_id)
                if nsg is None:
                    logging.debug(f"Azure NSG '{nsg_name} / {nsg_id}' was removed by user")
                    continue
                if nsg.restricted:
                    logging.debug(f"Azure NSG '{nsg_name} / {nsg_id}' issue was remediated by user")
                    continue

                if not batch and \
                   not confirm(f"Do you want to remediate Azure NSG '{nsg_name} / {nsg_id}'", False):
                    continue

                logging.debug(f"Remediating '{nsg_name} / {nsg_id}' rules")

                backup_path = nsg.backup_s3(main_account.client("s3"), backup_bucket)
                remediation_succeed = True
                processed = nsg.restrict(checker.client)
                if processed == 0:
                    logging.debug(f"No rules were detected to remediate in '{nsg_name} / {nsg_id}'")
                    continue
                elif processed is None:
                    remediation_succeed = False
                    comment = (f"Failed to remediate Azure NSG '{nsg_name}' issue "
                               f"in '{account_name} / {account_id}' subscription "
                               f"due to some limitations. Please, check manually")
                else:
                    comment = (f"Rules backup was saved to "
                               f"[{backup_path}|https://s3.console.aws.amazon.com/s3/object/{backup_bucket}/{backup_path}]. "
                               f"Azure NSG '{nsg_name}' unrestricted access issue "
                               f"in '{account_name} / {account_id}' subscription "
                               f"was remediated by hammer")

                self.remediator.report_remediation(issue, account_id, account_name, comment, remediation_succeed)
            except Exception:
                logging.exception(f"Error occurred while updating Azure NSG '{nsg_name} / {nsg_id}' rules "
                                  f"in '{account_name} / {account_id}'")


if __name__ == '__main__':
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
        obj = CleanAzureNSGIssues(config)
        obj.clean_azure_nsg_issues(batch=args.batch)
    except Exception:
        logging.exception("Failed to clean Azure NSG unrestricted access issues")
