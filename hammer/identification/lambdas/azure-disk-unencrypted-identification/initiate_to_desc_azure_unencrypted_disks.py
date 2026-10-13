import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find Azure unencrypted managed disks """
    set_logging(level=logging.INFO)
    logging.debug("Initiating Azure unencrypted managed disks checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.azureDisk.enabled:
            logging.debug("Azure unencrypted managed disks checking disabled")
            return

        logging.debug("Iterating over each subscription to initiate Azure unencrypted managed disks checking")
        for account_id, account_name in config.azureDisk.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "sns_arn": sns_arn
                      }
            logging.debug(f"Initiating Azure unencrypted managed disks checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of Azure unencrypted managed disks checking")
        return

    logging.debug("Azure unencrypted managed disks checking initiation done")
