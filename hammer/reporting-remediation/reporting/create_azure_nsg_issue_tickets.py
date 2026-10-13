"""
Class to create jira tickets for Azure network security groups unrestricted access issues.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.ddb_issues import AzureNSGIssue
from library.multicloud_reporting import MultiCloudTicketReporter
from library.utility import list_converter
from library.utility import SingletonInstance, SingletonInstanceException


class CreateAzureNSGTickets(MultiCloudTicketReporter):
    """ Class to create jira tickets for Azure NSG unrestricted access issues """
    resource_label = "Azure NSG"
    labels = ["azure-nsg-unrestricted-access"]
    priority = "Critical"
    recommendation = ("Restrict inbound access to the listed ports to specific trusted IP addresses/ranges "
                      "or virtual network service tags, use Azure Bastion/VPN for administrative access "
                      "or remove the rules if they are not required.")

    def issue_summary(self, issue, account_id, account_name):
        return (f"Azure NSG '{self.resource_name(issue)}' with unrestricted inbound access "
                f"in {self.account_title(account_id, account_name)}")

    def issue_description(self, issue, account_id, account_name):
        attached = bool(issue.issue_details.network_interfaces or issue.issue_details.subnets)
        risk = "High" if attached else "Medium"
        return (f"Azure network security group allows inbound access to sensitive ports from any address "
                f"in the Internet (`*`, `Internet`, `0.0.0.0/0` or `::/0` source).\n\n"
                f"*Threat*: "
                f"Services listening on these ports are exposed to brute force, vulnerability scanning "
                f"and exploitation attempts from the whole Internet.\n\n"
                f"*Risk*: {risk} "
                f"({'NSG is attached to network interfaces/subnets' if attached else 'NSG is not attached'})\n\n")

    def details_table(self, issue):
        rules = issue.issue_details.rules or []
        desc = ""
        if rules:
            desc += "*Unrestricted inbound rules*:\n"
            desc += "||Rule||Priority||Protocol||Ports||Source||\n"
            for rule in rules:
                desc += (f"|{rule.get('name')}|{rule.get('priority')}|{rule.get('protocol')}|"
                         f"{rule.get('ports')}|{rule.get('source')}|\n")
            desc += "\n"
        desc += f"*Attached network interfaces*: {list_converter(issue.issue_details.network_interfaces or [])}\n"
        desc += f"*Attached subnets*: {list_converter(issue.issue_details.subnets or [])}\n\n"
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
        obj = CreateAzureNSGTickets(config, config.azureNsg, AzureNSGIssue)
        obj.create_tickets()
    except Exception:
        logging.exception("Failed to create Azure NSG unrestricted access tickets")
