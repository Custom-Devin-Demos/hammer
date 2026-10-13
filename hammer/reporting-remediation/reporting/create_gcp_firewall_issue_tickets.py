"""
Class to create jira tickets for GCP firewall rules unrestricted access issues.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.ddb_issues import GCPFirewallIssue
from library.multicloud_reporting import MultiCloudTicketReporter
from library.utility import list_converter
from library.utility import SingletonInstance, SingletonInstanceException


class CreateGCPFirewallTickets(MultiCloudTicketReporter):
    """ Class to create jira tickets for GCP firewall rules with unrestricted access """
    resource_label = "GCP firewall rule"
    labels = ["insecure-services", "gcp-firewall"]
    priority = "Critical"
    recommendation = ("Restrict source ranges of the firewall rule to trusted networks only "
                      "(or use Identity-Aware Proxy / VPN / bastion host for administrative access) "
                      "and remove `0.0.0.0/0` / `::/0` for the listed protocols and ports.")

    def __init__(self, config):
        super().__init__(config, config.gcpFirewall, GCPFirewallIssue)

    def issue_summary(self, issue, account_id, account_name):
        return (f"GCP firewall rule '{self.resource_name(issue)}' with unrestricted access "
                f"in {self.account_title(account_id, account_name)}")

    def issue_description(self, issue, account_id, account_name):
        return (
            "GCP VPC firewall rule allows ingress traffic from the whole Internet (`0.0.0.0/0` / `::/0`) "
            "to ports which must not be publicly accessible.\n\n"
            "*Threat*: "
            "Services listening on these ports (SSH, RDP, databases, etc.) of all instances matching "
            "the rule targets are exposed to brute force, credentials stuffing and exploitation "
            "of known vulnerabilities from any Internet host.\n\n"
            "*Risk*: High\n\n"
        )

    def details_table(self, issue):
        details = issue.issue_details
        target_tags = list_converter(details.target_tags) if details.target_tags else "all instances"
        desc = (f"*Network*: {details.network}\n"
                f"*Priority*: {details.priority}\n"
                f"*Target Tags*: {target_tags}\n")
        if details.target_service_accounts:
            desc += f"*Target Service Accounts*: {list_converter(details.target_service_accounts)}\n"
        desc += "\n||Protocol||Ports||Source||\n"
        for rule in details.rules or []:
            desc += f"|{rule['protocol']}|{rule['ports']}|{rule['source']}|\n"
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
        obj = CreateGCPFirewallTickets(config)
        obj.create_tickets()
    except Exception:
        logging.exception("Failed to create GCP firewall rules tickets")
