"""
Class to create Azure unencrypted managed disk tickets.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.ddb_issues import AzureUnencryptedDiskIssue
from library.multicloud_reporting import MultiCloudTicketReporter
from library.azure.utility import parse_resource_id
from library.utility import empty_converter
from library.utility import SingletonInstance, SingletonInstanceException


class CreateAzureUnencryptedDiskTickets(MultiCloudTicketReporter):
    """ Class to create Azure unencrypted managed disk tickets """
    resource_label = "Azure Managed Disk"
    labels = ["azure-unencrypted-disks"]
    priority = "Major"
    recommendation = ("Encrypt managed disk with customer-managed key (Disk Encryption Set) "
                      "or enable Azure Disk Encryption on the virtual machine.")

    def __init__(self, config):
        super().__init__(config, config.azureDisk, AzureUnencryptedDiskIssue)

    def issue_summary(self, issue, account_id, account_name):
        return (f"Azure unencrypted managed disk '{self.resource_name(issue)}' "
                f"in {self.account_title(account_id, account_name)}")

    def issue_description(self, issue, account_id, account_name):
        if self.module_config.require_customer_managed_key:
            requirement = "is not encrypted with customer-managed key"
        else:
            requirement = "is encrypted only with platform-managed key (no customer-managed key and no Azure Disk Encryption)"
        return (f"Azure managed disk {requirement}.\n\n"
                f"*Threat*: Platform-managed keys are fully controlled by the cloud provider: "
                f"data owner can not control key access, rotation and revocation, "
                f"which does not satisfy compliance requirements (f.e. PCI) for encryption at rest.\n\n"
                f"*Risk*: Medium\n\n")

    def details_table(self, issue):
        details = issue.issue_details
        managed_by = details.managed_by
        if managed_by:
            managed_by = parse_resource_id(managed_by)["name"] or managed_by
        desc = "*Disk Details*:\n"
        desc += "||Resource ID||State||Attached To||SKU||Size (GB)||OS Type||Encryption Type||Disk Encryption Set||ADE||\n"
        desc += (f"|{issue.issue_id}"
                 f"|{empty_converter(details.state)}"
                 f"|{empty_converter(managed_by)}"
                 f"|{empty_converter(details.sku)}"
                 f"|{empty_converter(details.size_gb)}"
                 f"|{empty_converter(details.os_type)}"
                 f"|{empty_converter(details.encryption_type)}"
                 f"|{empty_converter(details.disk_encryption_set_id)}"
                 f"|{'enabled' if details.ade_enabled else 'disabled'}|\n")
        return desc


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
        obj = CreateAzureUnencryptedDiskTickets(config)
        obj.create_tickets()
    except Exception:
        logging.exception("Failed to create Azure unencrypted managed disk tickets")
