import os
import logging


from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find Azure network security groups unrestricted access """
    set_logging(level=logging.INFO)
    logging.debug("Initiating Azure NSG unrestricted access checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.azureNsg.enabled:
            logging.debug("Azure NSG unrestricted access checking disabled")
            return

        logging.debug("Iterating over each subscription to initiate Azure NSG unrestricted access check")
        for account_id, account_name in config.azureNsg.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating Azure NSG unrestricted access checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of Azure NSG unrestricted access checking")
        return

    logging.debug("Azure NSG unrestricted access checking initiation done")
