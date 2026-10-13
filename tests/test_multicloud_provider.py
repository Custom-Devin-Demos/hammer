import sys
import types
import pytest


from unittest import mock
from library.cloud import CloudProvider, CloudAccount
from library.aws.utility import Account
from library.azure.utility import AzureAccount, parse_resource_id
from library.gcp import utility as gcp_utility
from library.gcp.utility import GCPAccount, CLOUD_PLATFORM_SCOPE


AZURE_CREDS = {"tenant_id": "tenant", "client_id": "client", "client_secret": "secret"}
GCP_KEY = {"type": "service_account", "project_id": "proj", "client_email": "sa@proj.iam.gserviceaccount.com"}


def test_cloud_provider_values():
    assert CloudProvider("aws") is CloudProvider.AWS
    assert CloudProvider("azure") is CloudProvider.AZURE
    assert CloudProvider("gcp") is CloudProvider.GCP
    # str mixin allows comparison with plain strings from config
    assert CloudProvider.AZURE == "azure"
    assert str(CloudProvider.GCP) == "gcp"
    assert CloudProvider.AWS.account_label == "account"
    assert CloudProvider.AZURE.account_label == "subscription"
    assert CloudProvider.GCP.account_label == "project"


def test_cloud_account_str():
    assert str(CloudAccount("id1", "name1")) == "CloudAccount(id='id1', name='name1')"
    assert str(CloudAccount("id1")) == "CloudAccount(id='id1')"


def test_aws_account_provider():
    assert Account.provider is CloudProvider.AWS
    account = Account(id="123456789012", name="test", region="eu-west-1")
    assert account.provider is CloudProvider.AWS
    assert isinstance(account, CloudAccount)
    assert str(account) == "Account(id='123456789012', name='test', region='eu-west-1')"


@pytest.fixture
def fake_azure_identity():
    """ inject fake `azure.identity` module, so tests do not depend on/call real Azure SDK """
    credential_cls = mock.Mock(name="ClientSecretCredential")
    identity = types.ModuleType("azure.identity")
    identity.ClientSecretCredential = credential_cls
    azure = sys.modules.get("azure") or types.ModuleType("azure")
    with mock.patch.dict(sys.modules, {"azure": azure, "azure.identity": identity}):
        yield credential_cls


def test_azure_account_credential_and_client(fake_azure_identity):
    account = AzureAccount("sub-1", "prod", AZURE_CREDS)
    assert account.provider is CloudProvider.AZURE
    assert account.id == "sub-1" and account.name == "prod"

    credential = account.credential
    fake_azure_identity.assert_called_once_with(tenant_id="tenant", client_id="client", client_secret="secret")
    # cached
    assert account.credential is credential
    assert fake_azure_identity.call_count == 1

    client_cls = mock.Mock(name="StorageManagementClient")
    client = account.client(client_cls, api_version="2023-01-01")
    client_cls.assert_called_once_with(credential, "sub-1", api_version="2023-01-01")
    assert client is client_cls.return_value


def test_azure_account_missing_credentials(fake_azure_identity):
    account = AzureAccount("sub-1", "prod", {"tenant_id": "tenant"})
    assert account.credential is None
    fake_azure_identity.assert_not_called()
    with pytest.raises(RuntimeError):
        account.client(mock.Mock())


def test_azure_account_from_config():
    config = mock.Mock()
    config.azure.accounts = {"sub-1": "prod"}
    config.azure.credentials = AZURE_CREDS
    account = AzureAccount.from_config(config, "sub-1")
    assert (account.id, account.name, account.credentials) == ("sub-1", "prod", AZURE_CREDS)
    assert AzureAccount.from_config(config, "sub-2").name is None


@pytest.mark.parametrize("resource_id, expected", [
    ("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-1",
     {"subscription": "sub-1", "resource_group": "rg-1", "provider": "Microsoft.Network",
      "type": "networkSecurityGroups", "name": "nsg-1", "children": []}),
    ("/subscriptions/sub-1/resourcegroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-1/securityRules/r1",
     {"subscription": "sub-1", "resource_group": "rg-1", "provider": "Microsoft.Network",
      "type": "networkSecurityGroups", "name": "nsg-1", "children": [("securityRules", "r1")]}),
    ("/subscriptions/sub-1/resourceGroups/rg-1",
     {"subscription": "sub-1", "resource_group": "rg-1", "provider": None,
      "type": None, "name": None, "children": []}),
    ("",
     {"subscription": None, "resource_group": None, "provider": None,
      "type": None, "name": None, "children": []}),
])
def test_parse_resource_id(resource_id, expected):
    assert parse_resource_id(resource_id) == expected


@pytest.fixture
def fake_service_account():
    """ patch `google.oauth2.service_account` (inject fake module if google-auth is not installed) """
    try:
        from google.oauth2 import service_account
    except ImportError:
        service_account = None
    if service_account is not None:
        with mock.patch.object(service_account.Credentials, "from_service_account_info") as from_info:
            yield from_info
        return
    fake = types.ModuleType("google.oauth2.service_account")
    fake.Credentials = mock.Mock()
    oauth2 = types.ModuleType("google.oauth2")
    oauth2.service_account = fake
    google = types.ModuleType("google")
    google.oauth2 = oauth2
    with mock.patch.dict(sys.modules, {"google": google, "google.oauth2": oauth2,
                                       "google.oauth2.service_account": fake}):
        yield fake.Credentials.from_service_account_info


def test_gcp_account_credentials_and_client(fake_service_account):
    account = GCPAccount("proj", "prod", GCP_KEY)
    assert account.provider is CloudProvider.GCP

    credentials = account.credentials
    fake_service_account.assert_called_once_with(GCP_KEY, scopes=[CLOUD_PLATFORM_SCOPE])
    assert account.credentials is credentials
    assert fake_service_account.call_count == 1

    client_cls = mock.Mock(name="FirewallsClient")
    client = account.client(client_cls, project="proj")
    client_cls.assert_called_once_with(credentials=credentials, project="proj")
    assert client is client_cls.return_value


def test_gcp_account_missing_credentials(fake_service_account):
    account = GCPAccount("proj", "prod", {})
    assert account.credentials is None
    fake_service_account.assert_not_called()
    with pytest.raises(RuntimeError):
        account.client(mock.Mock())


def test_gcp_account_from_config():
    config = mock.Mock()
    config.gcp.accounts = {"proj": "prod"}
    config.gcp.credentials = GCP_KEY
    account = GCPAccount.from_config(config, "proj")
    assert (account.id, account.name, account.credentials_info) == ("proj", "prod", GCP_KEY)


def test_scope_constant():
    assert gcp_utility.CLOUD_PLATFORM_SCOPE == "https://www.googleapis.com/auth/cloud-platform"


def test_core_modules_do_not_import_cloud_sdks():
    import library.config
    import library.ddb_issues
    for module in (library.config, library.ddb_issues):
        source = open(module.__file__).read()
        assert "import azure" not in source and "from azure" not in source
        assert "import google" not in source and "from google" not in source
