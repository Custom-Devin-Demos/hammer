"""
Class to create Jira tickets for Azure storage accounts with not rotated access keys.
"""
import sys
import logging
import dateutil.parser


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.ddb_issues import AzureStorageKeyRotationIssue
from library.multicloud_reporting import MultiCloudTicketReporter
from library.utility import SingletonInstance, SingletonInstanceException


class CreateAzureStorageKeysRotationTickets(MultiCloudTicketReporter):
    """ Class to create Jira tickets for Azure storage account keys rotation issues """
    resource_label = "Azure storage account"
    labels = ["azure-storage-keys-rotation"]
    priority = "Major"
    recommendation = ("Switch applications using the specified access key(s) to the other key and "
                      "regenerate (rotate) the stale key(s). Prefer disabling shared key access and "
                      "using Azure AD authorization, and set up a key expiration policy for the storage account. ")

    def __init__(self, config):
        super().__init__(config, config.azureStorageKeys, AzureStorageKeyRotationIssue)

    @property
    def rotation_days(self):
        """ :return: number of days after which access key must be rotated """
        return self.module_config.rotation_criteria_days.days

    def issue_summary(self, issue, account_id, account_name):
        return (f"{self.resource_label} '{self.resource_name(issue)}' access keys have not been rotated "
                f"for {self.rotation_days} days "
                f"in {self.account_title(account_id, account_name)}")

    def issue_description(self, issue, account_id, account_name):
        return (f"{self.resource_label} access keys have not been rotated for {self.rotation_days} days "
                f"(or their creation time is unknown) while shared key access is allowed. "
                f"Storage account access keys grant full access to all data in the storage account, "
                f"leaked or long-lived keys can be used to read, modify or delete data.\n\n"
                f"*Risk*: Medium\n\n")

    @staticmethod
    def format_date(value):
        """ :return: human readable key creation time """
        if not value:
            return "unknown"
        return dateutil.parser.parse(value).replace(tzinfo=None).isoformat(' ', 'minutes')

    def details_table(self, issue):
        keys = issue.issue_details.keys or {}
        if not keys:
            return ""
        table = "*Stale Access Keys*:\n"
        table += "||Key Name||Created||\n"
        for key_name in sorted(keys):
            table += f"|{key_name}|{self.format_date(keys[key_name])}|\n"
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
        obj = CreateAzureStorageKeysRotationTickets(config)
        obj.create_tickets()
    except Exception:
        logging.exception("Failed to create Azure storage account keys rotation tickets")
