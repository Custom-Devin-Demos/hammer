import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find stale GCP service account keys """
    set_logging(level=logging.INFO)
    logging.debug("Initiating GCP service account keys rotation checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.gcpServiceAccountKeys.enabled:
            logging.debug("GCP service account keys rotation checking disabled")
            return

        logging.debug("Iterating over each project to initiate GCP service account keys rotation check")
        for project_id, project_name in config.gcpServiceAccountKeys.accounts.items():
            payload = {"account_id": project_id,
                       "account_name": project_name,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating GCP service account keys rotation checking for '{project_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of GCP service account keys rotation check")
        return

    logging.debug("GCP service account keys rotation checking initiation done")
