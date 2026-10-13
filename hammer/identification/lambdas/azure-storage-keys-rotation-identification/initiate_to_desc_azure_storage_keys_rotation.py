import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find Azure storage accounts with stale access keys """
    set_logging(level=logging.INFO)
    logging.debug("Initiating Azure storage account keys rotation checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.azureStorageKeys.enabled:
            logging.debug("Azure storage account keys rotation checking disabled")
            return

        logging.debug("Iterating over each subscription to initiate Azure storage account keys rotation check")
        for account_id, account_name in config.azureStorageKeys.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating Azure storage account keys rotation checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of Azure storage account keys rotation check")
        return

    logging.debug("Azure storage account keys rotation checking initiation done")
