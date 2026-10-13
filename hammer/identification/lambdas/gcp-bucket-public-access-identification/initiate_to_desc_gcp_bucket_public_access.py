import os
import logging

from library.logger import set_logging
from library.config import Config
from library.aws.utility import Sns


def lambda_handler(event, context):
    """ Lambda handler to initiate to find GCP buckets public access """
    set_logging(level=logging.INFO)
    logging.debug("Initiating GCP buckets public access checking")

    try:
        sns_arn = os.environ["SNS_ARN"]
        config = Config()

        if not config.gcpBucketPublic.enabled:
            logging.debug("GCP buckets public access checking disabled")
            return

        logging.debug("Iterating over each project to initiate GCP buckets public access check")
        for account_id, account_name in config.gcpBucketPublic.accounts.items():
            payload = {"account_id": account_id,
                       "account_name": account_name,
                       "sns_arn": sns_arn,
                      }
            logging.debug(f"Initiating GCP buckets public access checking for '{account_name}'")
            Sns.publish(sns_arn, payload)
    except Exception:
        logging.exception("Error occurred while initiation of GCP buckets public access checking")
        return

    logging.debug("GCP buckets public access checking initiation done")
