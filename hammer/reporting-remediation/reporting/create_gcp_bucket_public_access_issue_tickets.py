"""
Class to create GCP bucket public access tickets.
"""
import sys
import logging


from library.logger import set_logging, add_cw_logging
from library.config import Config
from library.ddb_issues import GCPBucketPublicAccessIssue
from library.multicloud_reporting import MultiCloudTicketReporter
from library.utility import SingletonInstance, SingletonInstanceException, list_converter


class CreateGCPBucketPublicAccessIssueTickets(MultiCloudTicketReporter):
    """ Class to create GCP bucket public access tickets """
    resource_label = "GCP bucket"
    labels = ["gcp-public-bucket"]
    priority = "Major"
    recommendation = (
        "Remove `allUsers`/`allAuthenticatedUsers` members from bucket IAM policy and legacy ACL, "
        "enable uniform bucket-level access and enforce public access prevention. "
        "Use signed URLs or Cloud CDN with a private bucket backend to share content publicly. "
    )

    def __init__(self, config):
        super().__init__(config, config.gcpBucketPublic, GCPBucketPublicAccessIssue)

    def issue_summary(self, issue, account_id, account_name):
        return f"GCP public bucket '{self.resource_name(issue)}' in {self.account_title(account_id, account_name)}"

    def issue_description(self, issue, account_id, account_name):
        return (
            "Bucket IAM policy or ACL allows public access to `allUsers` and/or `allAuthenticatedUsers`.\n\n"
            "*Threat*: "
            "Anyone on the Internet (or any Google account holder) can access bucket data according to granted roles, "
            "which can lead to data leakage, data tampering or unexpected egress costs.\n\n"
            "*Risk*: High\n\n"
        )

    def details_table(self, issue):
        details = issue.issue_details
        desc = ""
        public_bindings = details.public_bindings or {}
        if public_bindings:
            desc += "*Public IAM bindings*:\n"
            desc += "||Role||Members||\n"
            for role, members in public_bindings.items():
                desc += f"|{role}|{list_converter(members)}|\n"
        public_acls = details.public_acls or {}
        if public_acls:
            desc += "*Public ACL entries*:\n"
            desc += "||Entity||Roles||\n"
            for entity, roles in public_acls.items():
                desc += f"|{entity}|{list_converter(roles)}|\n"
        if details.public_access_prevention is not None:
            desc += f"*Public Access Prevention*: {details.public_access_prevention}\n"
        if details.uniform_bucket_level_access is not None:
            desc += f"*Uniform bucket-level access*: {'enabled' if details.uniform_bucket_level_access else 'disabled'}\n"
        return desc + "\n" if desc else ""


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
        obj = CreateGCPBucketPublicAccessIssueTickets(config)
        obj.create_tickets()
    except Exception:
        logging.exception("Failed to create GCP bucket public access tickets")
