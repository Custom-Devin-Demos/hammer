"""
Class to clean GCP firewall rules with unrestricted access
"""
import sys
import logging
import argparse


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.gcp.firewall import FirewallChecker
from library.aws.utility import Account
from library.ddb_issues import GCPFirewallIssue
from library.multicloud_reporting import MultiCloudIssueRemediator
from library.utility import confirm
from library.utility import SingletonInstance, SingletonInstanceException


class CleanGCPFirewallIssues(object):
    """ Class to clean GCP firewall rules with unrestricted access """
    def __init__(self, config):
        self.config = config
        self.remediator = MultiCloudIssueRemediator(config, config.gcpFirewall, GCPFirewallIssue)

    def clean_firewall_issues(self, batch=False):
        """ Class function to restrict GCP firewall rules which are open to the world for restricted ports """
        main_account = Account(region=self.config.aws.region)
        backup_bucket = self.config.aws.s3_backup_bucket

        for project_id, project_name, issue in self.remediator.candidates():
            rule_name = issue.issue_id
            try:
                account = self.remediator.account(project_id)
                if account.credentials is None:
                    continue

                checker = FirewallChecker(account=account,
                                          restricted_ports=self.config.gcpFirewall.restricted_ports)
                if not checker.check(ids=[rule_name]):
                    continue

                rule = checker.get_rule(rule_name)
                if rule is None:
                    logging.debug(f"Firewall rule '{rule_name}' was removed by user")
                    continue
                if rule.restricted:
                    logging.debug(f"Firewall rule '{rule_name}' issue was remediated by user")
                    continue

                if not batch and \
                   not confirm(f"Do you want to remediate firewall rule '{rule_name}' "
                               f"in '{project_name} / {project_id}' project", False):
                    continue

                logging.debug(f"Remediating '{rule_name}' firewall rule")

                backup_path = rule.backup_s3(main_account.client("s3"), backup_bucket)
                remaining = [cidr for cidr in rule.source_ranges if cidr not in rule.open_ranges]
                processed = rule.restrict()
                if processed == 0:
                    logging.debug(f"No source ranges were detected to remediate in '{rule_name}'")
                    continue
                elif processed is None:
                    remediation_succeed = False
                    comment = (f"Failed to remediate GCP firewall rule '{rule_name}' issue "
                               f"in '{project_name} / {project_id}' project "
                               f"due to some limitations. Please, check manually")
                else:
                    remediation_succeed = True
                    action = (f"source ranges were restricted to {remaining}" if remaining
                              else "rule was disabled as no restricted source ranges remained")
                    comment = (f"Rule backup was saved to "
                               f"[{backup_path}|https://s3.console.aws.amazon.com/s3/object/{backup_bucket}/{backup_path}]. "
                               f"GCP firewall rule '{rule_name}' unrestricted access issue "
                               f"in '{project_name} / {project_id}' project "
                               f"was remediated by hammer: open ranges {rule.open_ranges} were removed, {action}")

                self.remediator.report_remediation(issue, project_id, project_name, comment, remediation_succeed)
            except Exception:
                logging.exception(f"Error occurred while remediating firewall rule '{rule_name}' "
                                  f"in '{project_name} / {project_id}'")


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
        obj = CleanGCPFirewallIssues(config)
        obj.clean_firewall_issues(batch=args.batch)
    except Exception:
        logging.exception("Failed to clean GCP firewall rules")
