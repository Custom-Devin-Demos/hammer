"""
Class to create GCP service account keys rotation tickets.
"""
import sys
import logging
import dateutil.parser


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.ddb_issues import GCPServiceAccountKeyIssue
from library.multicloud_reporting import MultiCloudTicketReporter
from library.utility import SingletonInstance, SingletonInstanceException


class CreateGCPServiceAccountKeyRotationTickets(MultiCloudTicketReporter):
    """ Class to create GCP service account keys rotation tickets """
    resource_label = "GCP service account key"
    labels = ["gcp-sa-key-rotation"]
    priority = "Major"
    recommendation = ("Rotate the service account key: create a new key, update all applications "
                      "which use the old key and delete the old one. "
                      "Consider using workload identity / attached service accounts instead of user-managed keys.")

    def issue_summary(self, issue, account_id, account_name):
        return (f"GCP service account key '{self.resource_name(issue)}' rotation required "
                f"in '{account_name} / {account_id}' project")

    def issue_description(self, issue, account_id, account_name):
        rotation_days = self.module_config.rotation_criteria_days.days
        return (
            f"*Threat*: User-managed service account keys are long-lived credentials. "
            f"Keys that are not rotated regularly increase the window of opportunity for leaked/exposed keys "
            f"to be used for unauthorized access to GCP resources.\n\n"
            f"*Risk*: High\n\n"
            f"*Details*: user-managed key of '{issue.issue_details.service_account}' service account "
            f"was created more than {rotation_days} days ago.\n\n"
        )

    def key_age(self, issue):
        """ :return: key age in days (or 'unknown') """
        try:
            created = dateutil.parser.parse(issue.issue_details.created)
            return (self.config.now - created).days
        except Exception:
            return "unknown"

    def details_table(self, issue):
        details = issue.issue_details
        table = "||Service Account||Key ID||Key Resource Name||Created||Age (days)||Expires||\n"
        table += (f"|{details.service_account}"
                  f"|{details.key_id}"
                  f"|{issue.issue_id}"
                  f"|{details.created}"
                  f"|{self.key_age(issue)}"
                  f"|{details.expires or 'never'}|\n")
        return table


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

    try:
        obj = CreateGCPServiceAccountKeyRotationTickets(config, config.gcpServiceAccountKeys, GCPServiceAccountKeyIssue)
        obj.create_tickets()
    except Exception:
        logging.exception("Failed to create GCP service account keys rotation tickets")
