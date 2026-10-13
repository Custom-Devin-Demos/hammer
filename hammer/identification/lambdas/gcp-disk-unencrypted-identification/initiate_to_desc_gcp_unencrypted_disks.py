import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find GCP unencrypted disks """
    set_logging(level=logging.INFO)
    logging.debug("Initiating GCP unencrypted disks checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.gcpDisk.enabled:
            logging.debug("GCP unencrypted disks checking disabled")
            return

        logging.debug("Iterating over each project to initiate GCP unencrypted disks checking")
        for project_id, project_name in config.gcpDisk.accounts.items():
            # GCP APIs are global per project - no regions chaining
            payload = {"account_id": project_id,
                       "account_name": project_name,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating GCP unencrypted disks checking for '{project_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of GCP unencrypted disks checking")
        return

    logging.debug("GCP unencrypted disks checking initiation done")
