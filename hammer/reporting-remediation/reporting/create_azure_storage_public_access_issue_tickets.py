"""
Class to create Azure storage account public access tickets.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.ddb_issues import AzureStoragePublicAccessIssue
from library.multicloud_reporting import MultiCloudTicketReporter
from library.utility import SingletonInstance, SingletonInstanceException


class CreateAzureStoragePublicAccessTickets(MultiCloudTicketReporter):
    """ Class to create Azure storage account public access tickets """
    resource_label = "Azure storage account"
    labels = ["azure-public-storage"]
    priority = "Major"
    recommendation = (
        "Set public access level of the containers to 'Private (no anonymous access)' and "
        "disable 'Allow Blob anonymous access' on the storage account. "
        "Use shared access signatures (SAS), Azure AD authorization or Azure CDN with private origin "
        "to share data with specific consumers. "
    )

    def __init__(self, config):
        super().__init__(config, config.azureStoragePublic, AzureStoragePublicAccessIssue)

    def issue_summary(self, issue, account_id, account_name):
        return (f"Azure storage account '{self.resource_name(issue)}' with public blob containers "
                f"in {self.account_title(account_id, account_name)}")

    def issue_description(self, issue, account_id, account_name):
        return (
            "Azure storage account allows anonymous (public) read access to blob containers.\n\n"
            "*Threat*: "
            "Anyone on the Internet can list and/or read blobs in public containers without authorization, "
            "which can lead to sensitive data leakage.\n\n"
            "*Risk*: High\n\n"
        )

    def details_table(self, issue):
        public_containers = issue.issue_details.public_containers or {}
        desc = "*Public Containers*:\n"
        desc += "||Container||Public Access Level||\n"
        for container, level in public_containers.items():
            desc += f"|{container}|{level}|\n"
        return desc

    def create_tickets_azure_storage_public_access(self):
        """ Class method to create jira tickets """
        self.create_tickets()


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
        obj = CreateAzureStoragePublicAccessTickets(config)
        obj.create_tickets_azure_storage_public_access()
    except Exception:
        logging.exception("Failed to create Azure storage account public access tickets")
