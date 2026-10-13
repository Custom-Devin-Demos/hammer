"""
GCP provider helpers.

Google SDK packages are imported lazily, so this module can be imported
even when SDKs are not installed (e.g. in AWS-only lambdas).
"""
import logging


from library.cloud import CloudAccount, CloudProvider


CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


class GCPAccount(CloudAccount):
    """
    GCP project accessed with one service account.

    :param id: GCP project id
    :param name: project name (description from config)
    :param credentials: dict with service account JSON key
    """
    provider = CloudProvider.GCP

    def __init__(self, id, name=None, credentials=None):
        super().__init__(id, name)
        self.credentials_info = credentials or {}
        # variable for caching `google.oauth2.service_account.Credentials`
        self._credentials = None

    @property
    def credentials(self):
        """
        Lazily build `google.oauth2.service_account.Credentials` (cloud-platform scope) from service account key.

        :return: `Credentials` instance or None if key is missing/invalid
        """
        if self._credentials is None:
            if not self.credentials_info:
                logging.error(f"Failed to get credentials for {self}, 'gcp' credentials are empty")
                return None
            try:
                from google.oauth2 import service_account
                self._credentials = service_account.Credentials.from_service_account_info(
                    self.credentials_info,
                    scopes=[CLOUD_PLATFORM_SCOPE],
                )
            except Exception:
                logging.exception(f"Failed to get credentials for {self}")
                return None
        return self._credentials

    def client(self, client_cls, **kwargs):
        """
        Create GCP client with project service account credentials,
        f.e. `account.client(storage.Client, project=account.id)` or `account.client(compute_v1.FirewallsClient)`.

        :param client_cls: Google Cloud client class
        :param kwargs: extra arguments for client class

        :return: `client_cls(credentials=credentials, **kwargs)` instance
        """
        credentials = self.credentials
        if credentials is None:
            raise RuntimeError(f"No valid GCP credentials for {self}")
        return client_cls(credentials=credentials, **kwargs)

    @classmethod
    def from_config(cls, config, project_id):
        """
        :param config: `library.config.Config` instance
        :param project_id: GCP project id

        :return: `GCPAccount` with name and credentials from config
        """
        return cls(id=project_id,
                   name=config.gcp.accounts.get(project_id, None),
                   credentials=config.gcp.credentials)
