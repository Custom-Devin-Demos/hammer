import os
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find GCP firewall rules unrestricted access """
    set_logging(level=logging.INFO)
    logging.debug("Initiating GCP firewall rules checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.gcpFirewall.enabled:
            logging.debug("GCP firewall rules checking disabled")
            return

        logging.debug("Iterating over each project to initiate GCP firewall rules check")
        for project_id, project_name in config.gcpFirewall.accounts.items():
            payload = {"account_id": project_id,
                       "account_name": project_name,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating GCP firewall rules checking for '{project_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of GCP firewall rules checking")
        return

    logging.debug("GCP firewall rules checking initiation done")
