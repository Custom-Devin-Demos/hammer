"""
Class to create GCP unencrypted disk tickets.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.ddb_issues import GCPUnencryptedDiskIssue
from library.multicloud_reporting import MultiCloudTicketReporter
from library.utility import empty_converter, list_converter
from library.utility import SingletonInstance, SingletonInstanceException


class CreateGCPUnencryptedDiskTickets(MultiCloudTicketReporter):
    """ Class to create GCP unencrypted disk tickets """
    resource_label = "GCP disk"
    labels = ["gcp-unencrypted-disks"]
    priority = "Major"
    recommendation = ("Encrypt GCP disk with customer-managed encryption key (CMEK) from Cloud KMS: "
                      "create a snapshot of the disk and recreate the disk from it with `--kms-key` option.")

    def __init__(self, config):
        super().__init__(config, config.gcpDisk, GCPUnencryptedDiskIssue)

    def issue_summary(self, issue, account_id, account_name):
        return (f"GCP unencrypted disk '{issue.issue_id}' "
                f"in {self.account_title(account_id, account_name)}")

    def issue_description(self, issue, account_id, account_name):
        return ("GCP disk is encrypted only with Google-managed key, "
                "it needs to be encrypted with customer-managed (CMEK) or customer-supplied (CSEK) key.\n\n"
                "*Threat*: Without customer controlled keys you cannot audit, rotate, disable "
                "or revoke access to the key protecting disk data.\n\n"
                "*Risk*: High\n\n")

    def details_table(self, issue):
        details = issue.issue_details
        table = ("*Disk Details*:\n"
                 "||Disk ID||Status||Type||Size (GB)||Encryption||Attached Instances||\n"
                 f"|{issue.issue_id}"
                 f"|{empty_converter(details.status)}"
                 f"|{empty_converter(details.disk_type)}"
                 f"|{empty_converter(details.size_gb)}"
                 f"|{empty_converter(details.encryption)}"
                 f"|{list_converter(details.users) if details.users else 'none'}|\n")
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
        obj = CreateGCPUnencryptedDiskTickets(config)
        obj.create_tickets()
    except Exception:
        logging.exception("Failed to create GCP unencrypted disk tickets")
