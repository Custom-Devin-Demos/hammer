import json
import os
import pytest


from datetime import timedelta
from unittest import mock
from library.cloud import CloudProvider
from library.config import Config, ModuleConfig, AzureConfig, GCPConfig


CONFIGS_DIR = os.path.join(os.path.dirname(__file__), "..", "deployment", "configs")

NEW_MODULES = {
    "azureStoragePublic": ("azure_storage_public_access", CloudProvider.AZURE, "hammer-azure-storage-public-access"),
    "azureNsg": ("azure_nsg_unrestricted_access", CloudProvider.AZURE, "hammer-azure-nsg-unrestricted"),
    "azureDisk": ("azure_disk_unencrypted", CloudProvider.AZURE, "hammer-azure-disks-unencrypted"),
    "azureStorageKeys": ("azure_storage_keys_rotation", CloudProvider.AZURE, "hammer-azure-storage-keys-rotation"),
    "gcpBucketPublic": ("gcp_bucket_public_access", CloudProvider.GCP, "hammer-gcp-bucket-public-access"),
    "gcpFirewall": ("gcp_firewall_unrestricted_access", CloudProvider.GCP, "hammer-gcp-firewall-unrestricted"),
    "gcpDisk": ("gcp_disk_unencrypted", CloudProvider.GCP, "hammer-gcp-disks-unencrypted"),
    "gcpServiceAccountKeys": ("gcp_sa_keys_rotation", CloudProvider.GCP, "hammer-gcp-sa-keys-rotation"),
}

CREDENTIALS = {
    "azure": {"tenant_id": "t", "client_id": "c", "client_secret": "s"},
    "gcp": {"type": "service_account", "project_id": "p"},
}


def load_json(name):
    with open(os.path.join(CONFIGS_DIR, name)) as fh:
        return json.load(fh)


@pytest.fixture
def make_config(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")

    def _make(config_dict, whitelist=None, fixnow=None):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_dict))
        whitelist_file = tmp_path / "whitelist.json"
        whitelist_file.write_text(json.dumps(whitelist if whitelist is not None else load_json("whitelist.json")))
        fixnow_file = tmp_path / "fixnow.json"
        fixnow_file.write_text(json.dumps(fixnow or {}))
        loader = mock.Mock(side_effect=lambda table, region, key: CREDENTIALS.get(key, {}))
        with mock.patch.object(Config, "json_load_from_ddb", loader):
            config = Config(configFile=str(config_file),
                            configIniFile=str(tmp_path / "config.ini"),
                            whitelistFile=str(whitelist_file),
                            fixnowFile=str(fixnow_file),
                            ticketOwnersFile=str(tmp_path / "ticket_owners.json"))
        config._ddb_loader = loader
        return config
    return _make


def enabled_config():
    config = load_json("config.json")
    for _, (section, _, _) in NEW_MODULES.items():
        config[section]["enabled"] = True
        config[section]["reporting"] = True
        config[section]["remediation"] = True
    return config


def test_default_config_registers_new_modules(make_config):
    config = make_config(load_json("config.json"))
    for attr, (section, provider, table) in NEW_MODULES.items():
        module = getattr(config, attr)
        assert isinstance(module, ModuleConfig)
        assert module.name == section
        assert module.provider is provider
        assert module.ddb_table_name == table
        # shipped disabled
        assert not module.enabled
        assert not module.reporting
        assert not module.remediation
        assert config.get_module_config_by_name(section) is module
    assert config.azureNsg.restricted_ports == config.sg.restricted_ports
    assert config.gcpFirewall.restricted_ports == config.sg.restricted_ports
    assert config.azureStorageKeys.rotation_criteria_days == timedelta(days=90)
    assert config.gcpServiceAccountKeys.rotation_criteria_days == timedelta(days=90)
    assert config.azureDisk.require_customer_managed_key is False
    assert config.gcpBucketPublic.enforce_public_access_prevention is False
    assert config.cronjobs.get("python", "python3.6") == "python3.6"


def test_module_topics(make_config):
    config = make_config(load_json("config.json"))
    assert config.azureNsg.sns_topic_name == "hammer-describe-azure-nsg-lambda"
    assert config.gcpServiceAccountKeys.sns_topic_name == "hammer-describe-gcp-sa-keys-rotation-lambda"


def test_aws_modules_unchanged(make_config):
    config = make_config(load_json("config.json"))
    assert config.sg.provider is CloudProvider.AWS
    assert config.sg.enabled
    assert config.sg.accounts == load_json("config.json")["aws"]["accounts"]
    assert config.iamUserKeysRotation.rotation_criteria_days == timedelta(days=10)
    assert "654321210987" not in config.iamUserInactiveKeys.accounts
    assert set(config.sg.remediation_accounts) == {"210987654321", "654321210987"}


def test_provider_accounts_and_credentials(make_config):
    raw = enabled_config()
    config = make_config(raw)
    assert isinstance(config.azure, AzureConfig)
    assert isinstance(config.gcp, GCPConfig)
    assert config.azure.enabled and config.gcp.enabled
    assert config.azure.accounts == raw["azure"]["accounts"]
    assert config.gcp.accounts == raw["gcp"]["accounts"]
    # module accounts are resolved from provider section
    assert config.azureNsg.accounts == raw["azure"]["accounts"]
    assert config.gcpFirewall.accounts == raw["gcp"]["accounts"]
    assert config.azureNsg.enabled and config.azureNsg.reporting and config.azureNsg.remediation

    # credentials are loaded lazily from 'hammer-credentials' with 'azure'/'gcp' service keys
    called_keys = [call[0][2] for call in config._ddb_loader.call_args_list]
    assert "azure" not in called_keys and "gcp" not in called_keys
    with mock.patch.object(Config, "json_load_from_ddb", config._ddb_loader):
        assert config.azure.credentials == CREDENTIALS["azure"]
        assert config.gcp.credentials == CREDENTIALS["gcp"]
        # cached
        assert config.azure.credentials == CREDENTIALS["azure"]
    calls = [call[0] for call in config._ddb_loader.call_args_list]
    assert ("hammer-credentials", "eu-west-1", "azure") in calls
    assert ("hammer-credentials", "eu-west-1", "gcp") in calls
    assert sum(1 for call in calls if call[2] == "azure") == 1


def test_module_accounts_options(make_config):
    raw = enabled_config()
    raw["azure_nsg_unrestricted_access"]["accounts"] = ["00000000-0000-0000-0000-000000000001"]
    raw["gcp_firewall_unrestricted_access"]["ignore_accounts"] = ["example-dev-project"]
    raw["gcp_firewall_unrestricted_access"]["remediation_accounts"] = ["example-dev-project", "example-prod-project"]
    config = make_config(raw)
    assert config.azureNsg.accounts == {"00000000-0000-0000-0000-000000000001": "azure-prod"}
    assert config.gcpFirewall.accounts == {"example-prod-project": "gcp-prod"}
    assert config.gcpFirewall.remediation_accounts == {"example-prod-project": "gcp-prod"}


def test_whitelist_and_fixnow(make_config):
    whitelist = {"gcp_firewall_unrestricted_access": {"example-prod-project": ["allow-ssh"]}}
    fixnow = {"azure_storage_public_access": {"00000000-0000-0000-0000-000000000001": ["publicstorage"]}}
    config = make_config(enabled_config(), whitelist=whitelist, fixnow=fixnow)
    assert config.gcpFirewall.in_whitelist("example-prod-project", "allow-ssh")
    assert not config.gcpFirewall.in_whitelist("example-dev-project", "allow-ssh")
    assert config.azureStoragePublic.in_fixnow("00000000-0000-0000-0000-000000000001", "publicstorage")


def test_missing_provider_and_module_sections(make_config):
    raw = load_json("config.json")
    for section in ["azure", "gcp"] + [section for section, _, _ in NEW_MODULES.values()]:
        del raw[section]
    config = make_config(raw, whitelist={})
    assert not config.azure.enabled and not config.gcp.enabled
    assert config.azure.accounts == {} and config.gcp.accounts == {}
    assert config.azure.credentials == {} and config.gcp.credentials == {}
    called_keys = [call[0][2] for call in config._ddb_loader.call_args_list]
    assert "azure" not in called_keys and "gcp" not in called_keys
    for attr in NEW_MODULES:
        module = getattr(config, attr)
        assert not module.enabled
        assert not module.reporting
        assert not module.remediation
        assert module.accounts == {}
    assert config.azureNsg.restricted_ports == []
    assert config.gcpServiceAccountKeys.rotation_criteria_days == timedelta(days=90)
    # AWS modules still work
    assert config.sg.enabled


def test_provider_section_without_module_enabled(make_config):
    raw = enabled_config()
    raw["azure"]["enabled"] = False
    del raw["gcp"]
    config = make_config(raw)
    assert not config.azure.enabled
    assert not config.azureNsg.enabled and not config.azureNsg.reporting
    assert not config.gcpFirewall.enabled
    with mock.patch.object(Config, "json_load_from_ddb", config._ddb_loader):
        assert config.gcp.credentials == {}


def test_module_config_accepts_string_provider():
    raw = {"whitelist": {}, "fixnow": {}, "aws": {"accounts": {}},
           "gcp": {"accounts": {"p1": "one"}}, "gcp_disk_unencrypted": {"ddb.table_name": "t"}}
    module = ModuleConfig(raw, "gcp_disk_unencrypted", provider="gcp")
    assert module.provider is CloudProvider.GCP
    assert module.enabled
    assert module.accounts == {"p1": "one"}
    with pytest.raises(ValueError):
        ModuleConfig(raw, "gcp_disk_unencrypted", provider="oracle")
