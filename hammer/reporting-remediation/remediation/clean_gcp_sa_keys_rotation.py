"""
Class to remediate (disable) stale GCP service account keys.
"""
import sys
import logging
import argparse


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.ddb_issues import IssueStatus, GCPServiceAccountKeyIssue
from library.gcp.iam import GCPIAMOperations
from library.multicloud_reporting import MultiCloudIssueRemediator
from library.utility import confirm
from library.utility import SingletonInstance, SingletonInstanceException


class CleanGCPServiceAccountStaleKeys(MultiCloudIssueRemediator):
    """ Class to remediate (disable) stale GCP service account keys """
    def clean_service_account_keys(self, batch=False):
        """
        Disable reported stale user-managed service account keys.

        :param batch: boolean, if True - do not ask confirmation for remediation
        """
        for project_id, project_name, issue in self.candidates():
            key_name = issue.issue_id
            service_account = issue.issue_details.service_account
            title = f"'{key_name}' ('{service_account}')"

            if self.module_config.in_whitelist(project_id, service_account):
                logging.debug(f"Skipping {title} (service account in whitelist)")
                # Adding label with "whitelisted" to jira ticket.
                self.jira.add_label(
                    ticket_id=issue.jira_details.ticket,
                    label=IssueStatus.Whitelisted.value
                )
                continue

            try:
                if not batch and \
                   not confirm(f"Do you want to disable stale service account key {title}", False):
                    continue

                account = self.account(project_id)
                account.name = project_name
                if account.credentials is None:
                    continue

                iam_client = GCPIAMOperations.iam_client(account)
                key = GCPIAMOperations.get_service_account_key(iam_client, key_name)
                if key is None or key.disabled:
                    logging.debug(f"Skipping {title} (key does not exist or already disabled)")
                    continue

                logging.debug(f"Remediating stale service account key {title}")
                remediation_succeed = True
                try:
                    GCPIAMOperations.disable_service_account_key(iam_client, key_name)
                    comment = (f"Stale service account key {title} issue "
                               f"in '{project_name} / {project_id}' project "
                               f"was remediated by hammer (key was disabled)")
                except Exception:
                    remediation_succeed = False
                    logging.exception(f"Failed to disable {title} stale service account key")
                    comment = (f"Failed to remediate stale service account key {title} issue "
                               f"in '{project_name} / {project_id}' project "
                               f"due to some limitations. Please, check manually")

                self.report_remediation(issue, project_id, project_name, comment, remediation_succeed)
            except Exception:
                logging.exception(f"Error occurred while disabling {title} "
                                  f"in '{project_name} / {project_id}'")


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
        class_object = CleanGCPServiceAccountStaleKeys(config, config.gcpServiceAccountKeys, GCPServiceAccountKeyIssue)
        class_object.clean_service_account_keys(batch=args.batch)
    except Exception:
        logging.exception("Failed to clean stale GCP service account keys")
