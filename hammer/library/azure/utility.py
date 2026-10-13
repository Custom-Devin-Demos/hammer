"""
Azure provider helpers.

Azure SDK packages are imported lazily, so this module can be imported
even when SDKs are not installed (e.g. in AWS-only lambdas).
"""
import logging


from library.cloud import CloudAccount, CloudProvider


class AzureAccount(CloudAccount):
    """
    Azure subscription accessed with one service principal.

    :param id: Azure subscription id
    :param name: subscription name (description from config)
    :param credentials: dict with service principal `tenant_id`, `client_id`, `client_secret`
    """
    provider = CloudProvider.AZURE

    def __init__(self, id, name=None, credentials=None):
        super().__init__(id, name)
        self.credentials = credentials or {}
        # variable for caching `azure.identity.ClientSecretCredential`
        self._credential = None

    @property
    def credential(self):
        """
        Lazily build `azure.identity.ClientSecretCredential` from service principal credentials.

        :return: `ClientSecretCredential` instance or None if credentials are incomplete/invalid
        """
        if self._credential is None:
            missing = [key for key in ("tenant_id", "client_id", "client_secret") if not self.credentials.get(key)]
            if missing:
                logging.error(f"Failed to get credential for {self}, missing {missing} in 'azure' credentials")
                return None
            try:
                from azure.identity import ClientSecretCredential
                self._credential = ClientSecretCredential(
                    tenant_id=self.credentials["tenant_id"],
                    client_id=self.credentials["client_id"],
                    client_secret=self.credentials["client_secret"],
                )
            except Exception:
                logging.exception(f"Failed to get credential for {self}")
                return None
        return self._credential

    def client(self, client_cls, **kwargs):
        """
        Create Azure management client for current subscription,
        f.e. `account.client(StorageManagementClient)`.

        :param client_cls: Azure SDK management client class
        :param kwargs: extra arguments for client class

        :return: `client_cls(credential, subscription_id, **kwargs)` instance
        """
        credential = self.credential
        if credential is None:
            raise RuntimeError(f"No valid Azure credential for {self}")
        return client_cls(credential, self.id, **kwargs)

    @classmethod
    def from_config(cls, config, subscription_id):
        """
        :param config: `library.config.Config` instance
        :param subscription_id: Azure subscription id

        :return: `AzureAccount` with name and credentials from config
        """
        return cls(id=subscription_id,
                   name=config.azure.accounts.get(subscription_id, None),
                   credentials=config.azure.credentials)


def parse_resource_id(resource_id):
    """
    Parse Azure resource id like
    `/subscriptions/{sub}/resourceGroups/{rg}/providers/{namespace}/{type}/{name}[/{child type}/{child name}...]`

    :param resource_id: Azure resource id

    :return: dict with `subscription`, `resource_group`, `provider`, `type`, `name` (top level resource)
             and `children` (list of (type, name) tuples for nested resources). Missing parts are None.
    """
    result = {
        "subscription": None,
        "resource_group": None,
        "provider": None,
        "type": None,
        "name": None,
        "children": [],
    }
    if not resource_id:
        return result
    parts = [part for part in resource_id.strip("/").split("/") if part]
    i = 0
    while i < len(parts):
        key = parts[i].lower()
        value = parts[i + 1] if i + 1 < len(parts) else None
        if key == "subscriptions" and result["subscription"] is None:
            result["subscription"] = value
            i += 2
        elif key == "resourcegroups" and result["resource_group"] is None:
            result["resource_group"] = value
            i += 2
        elif key == "providers" and result["provider"] is None:
            result["provider"] = value
            rest = parts[i + 2:]
            pairs = [(rest[j], rest[j + 1] if j + 1 < len(rest) else None) for j in range(0, len(rest), 2)]
            if pairs:
                result["type"], result["name"] = pairs[0]
                result["children"] = pairs[1:]
            break
        else:
            i += 1
    return result
