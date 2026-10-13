import os
import sys
import json
import pytest


from types import SimpleNamespace
from unittest import mock
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.mgmt.compute.models import Disk, DiskProperties, Encryption, EncryptionSettingsCollection, DiskSku
from library.azure.compute import AzureDisk, AzureUnencryptedDisksChecker
from library.azure.utility import AzureAccount
from library.cloud import CloudProvider
from library.ddb_issues import IssueStatus, AzureUnencryptedDiskIssue


SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000001"
SUBSCRIPTION_NAME = "azure-prod"
DES_ID = f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-keys/providers/Microsoft.Compute/diskEncryptionSets/des-1"
VM_ID = f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/RG-1/providers/Microsoft.Compute/virtualMachines/vm-1"


def disk_id(name, resource_group="RG-1"):
    return f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{resource_group}/providers/Microsoft.Compute/disks/{name}"


def make_disk(name, encryption_type="EncryptionAtRestWithPlatformKey", des_id=None, ade=None, tags=None,
              managed_by=VM_ID):
    """ Build `azure.mgmt.compute.models.Disk` as installed Azure SDK returns it """
    properties = DiskProperties(
        disk_state="Attached",
        disk_size_gb=128,
        os_type="Linux",
        encryption=Encryption(type=encryption_type, disk_encryption_set_id=des_id),
    )
    if ade is not None:
        properties.encryption_settings_collection = EncryptionSettingsCollection(enabled=ade)
    return Disk(location="westeurope", properties=properties, sku=DiskSku(name="Premium_LRS"),
                tags=tags if tags is not None else {"owner": "alice"},
                id=disk_id(name), name=name, managed_by=managed_by)


def make_flat_disk(name, encryption_type="EncryptionAtRestWithPlatformKey", ade=False):
    """ Disk in flattened layout of older `azure-mgmt-compute` versions """
    return SimpleNamespace(
        id=disk_id(name), name=name, location="eastus", tags=None, managed_by=None,
        sku=SimpleNamespace(name="Standard_LRS"),
        disk_state="Unattached", disk_size_gb=32, os_type=None,
        encryption=SimpleNamespace(type=encryption_type, disk_encryption_set_id=None),
        encryption_settings_collection=SimpleNamespace(enabled=ade),
        security_profile=None,
    )


DISKS = {
    # name: (disk, compliant by default, compliant with require_customer_managed_key)
    "platform-key": (make_disk("platform-key"), False, False),
    "customer-key": (make_disk("customer-key", "EncryptionAtRestWithCustomerKey", DES_ID), True, True),
    "double-key": (make_disk("double-key", "EncryptionAtRestWithPlatformAndCustomerKeys", DES_ID), True, True),
    "ade-enabled": (make_disk("ade-enabled", ade=True), True, False),
    "ade-disabled": (make_disk("ade-disabled", ade=False), False, False),
    "flat-platform-key": (make_flat_disk("flat-platform-key"), False, False),
    "flat-ade": (make_flat_disk("flat-ade", ade=True), True, False),
}


def make_account(disks=None):
    account = mock.Mock()
    account.id = SUBSCRIPTION_ID
    client = mock.Mock()
    client.disks.list.return_value = iter(disks if disks is not None else [d for d, _, _ in DISKS.values()])
    account.client.return_value = client
    return account, client


@pytest.mark.parametrize("name", DISKS.keys())
def test_disk_encryption(name):
    source, compliant, compliant_cmk = DISKS[name]
    disk = AzureDisk(None, source)
    assert disk.compliant() == compliant
    assert disk.compliant(require_customer_managed_key=True) == compliant_cmk


def test_disk_attributes():
    disk = AzureDisk(None, DISKS["customer-key"][0])
    assert disk.id == disk_id("customer-key").lower()
    assert disk.name == "customer-key"
    assert disk.location == "westeurope"
    assert disk.resource_group == "RG-1"
    assert disk.tags == {"owner": "alice"}
    assert disk.state == "Attached"
    assert disk.sku == "Premium_LRS"
    assert disk.size_gb == 128
    assert disk.os_type == "Linux"
    assert disk.encryption_type == "EncryptionAtRestWithCustomerKey"
    assert disk.disk_encryption_set_id == DES_ID
    assert disk.managed_by == VM_ID
    flat = AzureDisk(None, DISKS["flat-platform-key"][0])
    assert flat.tags == {}
    assert flat.state == "Unattached"
    assert flat.encryption_type == "EncryptionAtRestWithPlatformKey"


def test_confidential_vm_customer_key():
    source = make_disk("cvm")
    source.properties.security_profile = SimpleNamespace(security_type="ConfidentialVM_DiskEncryptedWithCustomerKey")
    assert AzureDisk(None, source).compliant(require_customer_managed_key=True)


@pytest.mark.parametrize("require_cmk,expected", [
    (False, {"platform-key", "ade-disabled", "flat-platform-key"}),
    (True, {"platform-key", "ade-disabled", "flat-platform-key", "ade-enabled", "flat-ade"}),
])
def test_checker(require_cmk, expected):
    account, client = make_account()
    checker = AzureUnencryptedDisksChecker(account, require_customer_managed_key=require_cmk)
    assert checker.check()
    assert len(checker.disks) == len(DISKS)
    assert {disk.name for disk in checker.unencrypted_disks} == expected
    assert checker.get_disk(disk_id("platform-key").upper()).name == "platform-key"
    assert checker.get_disk("unknown") is None


def test_checker_uses_compute_client():
    account, client = make_account()
    from library.azure import compute
    AzureUnencryptedDisksChecker(account).check()
    account.client.assert_called_once_with(compute.ComputeManagementClient)


def test_checker_tags_filter():
    account, _ = make_account([make_disk("a", tags={"env": "prod"}), make_disk("b", tags={"env": "dev"}),
                               make_disk("c", tags={})])
    checker = AzureUnencryptedDisksChecker(account)
    assert checker.check(tags={"env": ["prod", "qa"]})
    assert [disk.name for disk in checker.disks] == ["a"]


def test_checker_ids():
    account, client = make_account()
    found = make_disk("platform-key")

    def get(resource_group, name):
        if name == "platform-key":
            return found
        raise ResourceNotFoundError("not found")
    client.disks.get.side_effect = get
    checker = AzureUnencryptedDisksChecker(account)
    assert checker.check(ids=[disk_id("platform-key"), disk_id("missing")])
    client.disks.list.assert_not_called()
    client.disks.get.assert_any_call("RG-1", "platform-key")
    assert [disk.name for disk in checker.disks] == ["platform-key"]


@pytest.mark.parametrize("error", [
    HttpResponseError(message="forbidden", response=mock.Mock(status_code=403, reason="Forbidden")),
    HttpResponseError(message="boom", response=mock.Mock(status_code=500, reason="Error")),
    RuntimeError("No valid Azure credential"),
])
def test_checker_failure(error):
    account, client = make_account()
    client.disks.list.side_effect = error
    checker = AzureUnencryptedDisksChecker(account)
    assert not checker.check()
    assert checker.disks == []


def test_checker_with_azure_account():
    """ checker works with real `AzureAccount.client` wrapper (SDK client class is mocked) """
    account = AzureAccount(SUBSCRIPTION_ID, SUBSCRIPTION_NAME, {})
    account._credential = mock.sentinel.credential
    client_cls = mock.Mock()
    client_cls.return_value.disks.list.return_value = [make_disk("platform-key")]
    with mock.patch("library.azure.compute.ComputeManagementClient", client_cls):
        checker = AzureUnencryptedDisksChecker(account)
        assert checker.check()
    client_cls.assert_called_once_with(mock.sentinel.credential, SUBSCRIPTION_ID)
    assert [disk.name for disk in checker.unencrypted_disks] == ["platform-key"]


# ---------- identification lambdas ----------

def make_config(enabled=True, require_cmk=False, whitelist=()):
    config = mock.Mock()
    config.aws.region = "us-east-1"
    config.azure.credentials = {"tenant_id": "t", "client_id": "c", "client_secret": "s"}
    config.azureDisk.enabled = enabled
    config.azureDisk.accounts = {SUBSCRIPTION_ID: SUBSCRIPTION_NAME, "sub-2": "azure-dev"}
    config.azureDisk.ddb_table_name = "hammer-azure-disks-unencrypted"
    config.azureDisk.require_customer_managed_key = require_cmk
    config.azureDisk.in_whitelist.side_effect = lambda account_id, issue_id: issue_id in whitelist
    return config


def sns_event(payload):
    return {"Records": [{"Sns": {"Message": json.dumps(payload)}}]}


@pytest.mark.parametrize("enabled", [True, False])
def test_initiate(enabled, monkeypatch):
    import initiate_to_desc_azure_unencrypted_disks as initiate
    monkeypatch.setenv("SNS_ARN", "arn:sns")
    with mock.patch.object(initiate, "Config", return_value=make_config(enabled=enabled)), \
         mock.patch.object(initiate, "Sns") as sns:
        initiate.lambda_handler({}, None)
    if not enabled:
        sns.publish.assert_not_called()
        return
    assert sns.publish.call_count == 2
    sns.publish.assert_any_call("arn:sns", {"account_id": SUBSCRIPTION_ID,
                                            "account_name": SUBSCRIPTION_NAME,
                                            "sns_arn": "arn:sns"})


def run_describe(config, disks, open_issues=(), request_id=None, credential=True):
    import describe_azure_unencrypted_disks as describe
    account, client = make_account(disks)
    account.provider = CloudProvider.AZURE
    account.credential = mock.sentinel.credential if credential else None
    payload = {"account_id": SUBSCRIPTION_ID, "account_name": SUBSCRIPTION_NAME, "sns_arn": "arn:sns"}
    if request_id:
        payload["request_id"] = request_id
    with mock.patch.object(describe, "Config", return_value=config), \
         mock.patch.object(describe, "Account") as main_account, \
         mock.patch.object(describe, "AzureAccount", return_value=account) as azure_account, \
         mock.patch.object(describe, "DDB") as ddb, \
         mock.patch.object(describe, "IssueOperations") as ops:
        ops.get_account_open_issues.return_value = list(open_issues)
        describe.lambda_handler(sns_event(payload), None)
    azure_account.assert_called_once_with(id=SUBSCRIPTION_ID, name=SUBSCRIPTION_NAME,
                                          credentials=config.azure.credentials)
    return ops, ddb, main_account


def test_describe_upserts_and_resolves():
    whitelisted = disk_id("ade-disabled").lower()
    stale = AzureUnencryptedDiskIssue(SUBSCRIPTION_ID, disk_id("deleted").lower())
    still_open = AzureUnencryptedDiskIssue(SUBSCRIPTION_ID, disk_id("platform-key").lower())
    config = make_config(whitelist=(whitelisted,))
    ops, ddb, _ = run_describe(config, [DISKS["platform-key"][0], DISKS["customer-key"][0],
                                        DISKS["ade-enabled"][0], DISKS["ade-disabled"][0]],
                               open_issues=[stale, still_open])

    issues = {call.args[1].issue_id: call.args[1] for call in ops.update.call_args_list}
    assert set(issues) == {disk_id("platform-key").lower(), whitelisted}
    issue = issues[disk_id("platform-key").lower()]
    assert isinstance(issue, AzureUnencryptedDiskIssue)
    assert issue.account_id == SUBSCRIPTION_ID
    assert issue.status == IssueStatus.Open
    details = issue.issue_details
    assert details.provider == "azure"
    assert details.name == "platform-key"
    assert details.location == "westeurope"
    assert details.resource_group == "RG-1"
    assert details.tags == {"owner": "alice"}
    assert details.encryption_type == "EncryptionAtRestWithPlatformKey"
    assert details.ade_enabled is False
    assert details.managed_by == VM_ID
    json.dumps(issue.as_dict())
    assert issues[whitelisted].status == IssueStatus.Whitelisted

    ops.set_status_resolved.assert_called_once()
    assert ops.set_status_resolved.call_args.args[1] is stale
    ddb.track_progress.assert_not_called()


def test_describe_require_cmk():
    ops, _, _ = run_describe(make_config(require_cmk=True), [DISKS["ade-enabled"][0], DISKS["customer-key"][0]])
    assert [call.args[1].issue_details.name for call in ops.update.call_args_list] == ["ade-enabled"]


def test_describe_check_failure_does_not_resolve():
    import describe_azure_unencrypted_disks as describe
    stale = AzureUnencryptedDiskIssue(SUBSCRIPTION_ID, disk_id("deleted").lower())
    with mock.patch.object(describe.AzureUnencryptedDisksChecker, "check", return_value=False):
        ops, _, _ = run_describe(make_config(), [], open_issues=[stale])
    ops.update.assert_not_called()
    ops.set_status_resolved.assert_not_called()


def test_describe_api_request_tracking():
    _, ddb, main_account = run_describe(make_config(), [DISKS["customer-key"][0]], request_id="req-1")
    ddb.track_progress.assert_called_once()
    assert ddb.track_progress.call_args.args[1] == "req-1"


def test_describe_no_credential():
    ops, ddb, _ = run_describe(make_config(), [DISKS["platform-key"][0]], credential=False)
    ops.update.assert_not_called()
    ops.get_account_open_issues.assert_not_called()


# ---------- reporting ----------

@pytest.fixture
def reporting_path():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "hammer", "reporting-remediation"))
    try:
        yield
    finally:
        sys.path.pop(0)


def test_reporting_description(reporting_path):
    from reporting.create_azure_unencrypted_disk_issue_tickets import CreateAzureUnencryptedDiskTickets
    config = mock.Mock()
    config.whitelisting_procedure_url = None
    config.azureDisk.provider = CloudProvider.AZURE
    config.azureDisk.remediation = False
    config.azureDisk.require_customer_managed_key = False
    reporter = CreateAzureUnencryptedDiskTickets(config)
    assert reporter.module_config is config.azureDisk
    assert reporter.issue_class is AzureUnencryptedDiskIssue

    issue = AzureUnencryptedDiskIssue(SUBSCRIPTION_ID, disk_id("platform-key").lower())
    issue.issue_details.name = "platform-key"
    issue.issue_details.location = "westeurope"
    issue.issue_details.resource_group = "RG-1"
    issue.issue_details.managed_by = VM_ID
    issue.issue_details.encryption_type = "EncryptionAtRestWithPlatformKey"
    issue.issue_details.tags = {"owner": "alice"}

    summary = reporter.issue_summary(issue, SUBSCRIPTION_ID, SUBSCRIPTION_NAME)
    assert "platform-key" in summary and SUBSCRIPTION_ID in summary
    desc = reporter.build_description(issue, SUBSCRIPTION_ID, SUBSCRIPTION_NAME, "alice")
    for text in ["*Cloud Provider*: Azure", f"*Subscription ID*: {SUBSCRIPTION_ID}", "*Location*: westeurope",
                 "*Resource Group*: RG-1", "|owner|alice|", "|vm-1|", "EncryptionAtRestWithPlatformKey",
                 "*Risk*", "*Recommendation*", "platform-managed key"]:
        assert text in desc
    assert reporter.get_labels() == ["azure-unencrypted-disks"]
