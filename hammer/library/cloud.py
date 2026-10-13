"""
Cloud provider abstractions shared by AWS, Azure and GCP modules.

Hammer generalises "account" to the provider specific scope:
AWS account id / Azure subscription id / GCP project id.
"""
from enum import Enum


class CloudProvider(str, Enum):
    """ Supported cloud providers (values are used as config section names) """
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"

    def __str__(self):
        return self.value

    @property
    def account_label(self):
        """ :return: human readable name of the provider "account" scope """
        return {
            CloudProvider.AWS: "account",
            CloudProvider.AZURE: "subscription",
            CloudProvider.GCP: "project",
        }[self]


class CloudAccount(object):
    """
    Base class for cloud "accounts" (AWS account / Azure subscription / GCP project).
    Encapsulates provider / ID / name.
    """
    provider = None

    def __init__(self, id, name=None):
        self.id = id
        self.name = name

    def __str__(self):
        name = f", name='{self.name}'" if self.name else ""
        return f"{self.__class__.__name__}(id='{self.id}'{name})"
