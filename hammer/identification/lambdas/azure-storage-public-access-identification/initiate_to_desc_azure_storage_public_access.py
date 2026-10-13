import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find Azure storage accounts with public blob containers """
    set_logging(level=logging.INFO)
    logging.debug("Initiating Azure storage accounts public access checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.azureStoragePublic.enabled:
            logging.debug("Azure storage accounts public access checking disabled")
            return

        logging.debug("Iterating over each subscription to initiate Azure storage accounts public access check")
        for account_id, account_name in config.azureStoragePublic.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating Azure storage accounts public access checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of Azure storage accounts public access checking")
        return

    logging.debug("Azure storage accounts public access checking initiation done")
