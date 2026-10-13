---
title: Azure Unencrypted Managed Disks
keywords: playbook16
sidebar: mydoc_sidebar
permalink: playbook16_azure_unencrypted_disks.html
---

# Playbook 16: Azure Unencrypted Managed Disks

## Introduction

This playbook describes how to configure Dow Jones Hammer to detect Azure managed disks that are encrypted at rest only with platform-managed keys (the Azure equivalent of [EBS Unencrypted Volumes](playbook7_ebs_unencrypted_volumes.html)).

Azure always encrypts managed disks at rest with platform-managed keys (server-side encryption). Platform-managed keys are fully controlled by Microsoft, so data owners can not control key access, rotation and revocation, which usually does not satisfy compliance requirements (f.e. PCI). Dow Jones Hammer treats such disks as unencrypted.

## 1. Issue Identification

Dow Jones Hammer lists all managed disks in each configured Azure subscription and treats a disk as **compliant** when it is encrypted with:
* a **customer-managed key** - `encryption.type` is `EncryptionAtRestWithCustomerKey` or `EncryptionAtRestWithPlatformAndCustomerKeys` (Disk Encryption Set is attached), or the disk is a confidential VM disk with `ConfidentialVM_DiskEncryptedWithCustomerKey` security type;
* or **Azure Disk Encryption** (ADE, BitLocker/DM-Crypt inside the VM) - `encryption_settings_collection.enabled` is `true`.

Disks encrypted only with the platform-managed key (`EncryptionAtRestWithPlatformKey` and no ADE) are reported as issues. When `require_customer_managed_key` is `true`, ADE is not enough and only customer-managed key encryption passes.

Issue ID is the disk resource ID in lower case, f.e. `/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-1/providers/microsoft.compute/disks/vm-1_osdisk`.

When Dow Jones Hammer detects an issue, it writes the issue to the designated DynamoDB table. Issues for disks which were deleted or encrypted since the previous check are marked as resolved.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions (running in the Hammer AWS account, Azure APIs are called with the service principal credentials from the `hammer-credentials` DynamoDB table).
Azure APIs are global per subscription, so there is no region chaining: one identification Lambda invocation checks one subscription.
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/azure-disk-unencrypted-identification/initiate_to_desc_azure_unencrypted_disks.py`|
|Identification|`hammer/identification/lambdas/azure-disk-unencrypted-identification/describe_azure_unencrypted_disks.py`|
|Checker       |`hammer/library/azure/compute.py`|


## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

The JIRA ticket contains the cloud provider, subscription name/ID, disk name, location, resource group, a table with disk details (state, attached VM, SKU, size, OS type, encryption type, Disk Encryption Set, ADE status), disk tags, risk and recommendation.

Additionally Dow Jones Hammer tries to detect person to report issue to by examining `owner` tag on affected managed disk (`bu` and `product` tags are used the same way as for AWS resources). In case when such tag **exists** and is **valid JIRA/Slack user**:
* for JIRA: `jira_owner` parameter from [ticket_owners.json](#43-the-ticket_ownersjson-file) **is ignored** and discovered `owner` **is used instead** as a JIRA assignee;
* for Slack: discovered `owner` **is used in addition to** `slack_owner` value from [ticket_owners.json](#43-the-ticket_ownersjson-file).

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_azure_unencrypted_disk_issue_tickets.py
```

## 3. Issue Remediation

In this specific case, automated remediation **is not available**. Encrypting existing disks with a customer-managed key requires a Disk Encryption Set and (for attached disks) a VM deallocation, so it must be planned by the resource owner:
* customer-managed key: create a [Disk Encryption Set](https://docs.microsoft.com/en-us/azure/virtual-machines/disk-encryption) backed by Key Vault and update disk encryption to `EncryptionAtRestWithCustomerKey`;
* or enable [Azure Disk Encryption](https://docs.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview) on the virtual machine.

## 4. Setup Instructions For This Issue

To configure the detection, reporting, and remediation of this issue, you should edit the following sections of the Dow Jones Hammer configuration files:

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
Subscriptions to check are taken from the `azure` section (`accounts` - {subscription id: name}).
To identify, report, and remediate issues of this type, you should add the following parameters in the **azure_disk_unencrypted** section of the **config.json** file:

|Parameter Name|Description|Default Value|
|----------------|----------------------------------------------------------------------------------------|:-------------------------------:|
|`enabled`       |Toggles issue detection for this issue                                                  |`false`                          |
|`ddb.table_name`|The name of the DynamoDB table to which Dow Jones Hammer would record detected issues of this type|`hammer-azure-disks-unencrypted` |
|`topic_name`    |The name of SNS topic to trigger identification Lambda                                  |`hammer-describe-azure-unencrypted-disks-lambda`|
|`accounts`      |*Optional* comma-separated list of subscriptions to limit check for                     |`azure.accounts` from `config.json`|
|`ignore_accounts`|*Optional* comma-separated list of subscriptions to exclude from check                 |`[]`                             |
|`require_customer_managed_key`|If `true` - only customer-managed key encryption is acceptable (ADE is not enough)|`false`              |
|`reporting`     |Toggle Dow Jones Hammer reporting functionality for this issue                          |`false`                          |

Sample **config.json** section:
```
"azure": {
    "accounts": {
        "00000000-0000-0000-0000-000000000000": "azure-prod"
    }
},
"azure_disk_unencrypted": {
    "enabled": true,
    "ddb.table_name": "hammer-azure-disks-unencrypted",
    "topic_name": "hammer-describe-azure-unencrypted-disks-lambda",
    "require_customer_managed_key": false,
    "reporting": true,
    "remediation": false
}
```

### 4.2. The whitelist.json File

You can define exceptions to issue detection settings for specific managed disks. To configure such exceptions, you should edit the **azure_disk_unencrypted** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s) |
|:----:|:-----:|
|Azure Subscription ID|Disk resource IDs (lower case)|

Sample **whitelist.json** section:
```
"azure_disk_unencrypted": {
    "00000000-0000-0000-0000-000000000000": ["/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-1/providers/microsoft.compute/disks/vm-1_osdisk"]
}
```

### 4.3. The ticket_owners.json File

You should use the **ticket_owners.json** file to configure the integration of Dow Jones Hammer with JIRA and/or Slack for issue reporting purposes.

You can configure these parameters for specific Azure subscriptions (use subscription ID as `account` key) and globally. Subscription-specific settings precede the global settings in the **ticket_owners.json** configuration file.

Check the following table for parameters:

|Parameter Name       |Description                                                         |Sample Value     |
|---------------------|--------------------------------------------------------------------|:---------------:|
|`jira_project`       |The name of the JIRA project where Dow Jones Hammer will create the issue     | `AWSSEC`        |
|`jira_owner`         |The name of the JIRA user to whom Dow Jones Hammer will assign the issue      | `Support-Cloud` |
|`jira_parent_ticket` |The JIRA ticket to which Dow Jones Hammer will link the new ticket it creates | `AWSSEC-1234`   |
|`slack_owner`        |Name(s) of the Slack channels (prefixed by `#`) and/or Slack users that will receive issue reports from Dow Jones Hammer | `["#devops-channel", "bob"]` |

Sample **ticket_owners.json** section:

Subscription-specific settings:
```
{
    "account": {
        "00000000-0000-0000-0000-000000000000": {
            "jira_project": "",
            "jira_owner": "Support-Cloud",
            "jira_parent_ticket": "",
            "slack_owner": ""
        }
    },
    "jira_project": "AWSSEC",
    "jira_owner": "Support-General",
    "jira_parent_ticket": "AWSSEC-1234",
    "slack_owner": ["#devops-channel", "bob"]
}
```

### 4.4. Required Azure Permissions

The Hammer service principal (credentials are stored under the `azure` key of the `hammer-credentials` DynamoDB table) needs read access to managed disks in every configured subscription:

|Action|Purpose|
|------|-------|
|`Microsoft.Compute/disks/read`|List managed disks and their encryption settings|

The built-in **Reader** role on the subscription is sufficient. Identification Lambda package installs `azure-identity` and `azure-mgmt-compute` (see `requirements.txt` in the Lambda directory).

## 5. Logging

Dow Jones Hammer uses **CloudWatch Logs** for logging purposes.

Dow Jones Hammer automatically sets up CloudWatch Log Groups and Log Streams for this issue when you deploy Dow Jones Hammer.

### 5.1. Issue Identification Logging

Dow Jones Hammer issue identification functionality uses two Lambda functions:

* Initialization: this Lambda function selects Azure subscriptions to check for this issue as designated in the Dow Jones Hammer configuration files and triggers the check.
* Identification: this Lambda function identifies this issue for each subscription selected at the previous step.

You can see the logs for each of these Lambda functions in the following Log Groups:

|Lambda Function|CloudWatch Log Group Name                            |
|---------------|-----------------------------------------------------|
|Initialization |`/aws/lambda/hammer-initiate-azure-unencrypted-disks`|
|Identification |`/aws/lambda/hammer-describe-azure-unencrypted-disks`|

### 5.2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name                        |
|-----------|--------------------------------------------------|
|Reporting  |`reporting.create_azure_unencrypted_disk_issue_tickets`|

### 5.3. Slack Reports

In case you have enabled Dow Jones Hammer and Slack integration, Dow Jones Hammer sends notifications about issue identification and remediation to the designated Slack channel and/or recipient(s).

Check [ticket_owners.json](#43-the-ticket_ownersjson-file) configuration for further guidance.

### 5.4. Using CloudWatch Logs for Dow Jones Hammer

To access Dow Jones Hammer logs, proceed as follows:

1. Open **AWS Management Console**.
2. Select **CloudWatch** service.
3. Select **Logs** from the CloudWatch sidebar.
4. Select the log group you want to explore. The log group will open.
5. Select the log stream you want to explore.

Check [CloudWatch Logs documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html) for further guidance.

## 6. Issue specific details in DynamoDB

Dow Jones Hammer stores various issue specific details in DynamoDB as a map under `issue_details` key. You can use it to create your own reporting modules.

|Key          |Type  |Description                                                |Example                          |
|-------------|:----:|-----------------------------------------------------------|---------------------------------|
|`provider`   |string|Cloud provider                                             |`azure`                          |
|`name`       |string|Managed disk name                                          |`vm-1_OsDisk`                    |
|`location`   |string|Azure location where disk exists                           |`westeurope`                     |
|`resource_group`|string|Resource group of the disk                              |`rg-1`                           |
|`state`      |string|Disk state                                                 |`Attached`                       |
|`managed_by` |string|Resource ID of the VM the disk is attached to              |`/subscriptions/.../virtualMachines/vm-1`|
|`sku`        |string|Disk SKU                                                   |`Premium_LRS`                    |
|`size_gb`    |number|Disk size in GB                                            |`128`                            |
|`os_type`    |string|OS type for OS disks                                       |`Linux`                          |
|`encryption_type`|string|Encryption at rest type                                |`EncryptionAtRestWithPlatformKey`|
|`disk_encryption_set_id`|string|Disk Encryption Set resource ID (customer-managed key)|`null`                     |
|`ade_enabled`|boolean|If Azure Disk Encryption is enabled                       |`false`                          |
|`tags`       |map   |Tags associated with disk                                  |`{"owner": "alice", "bu": "news"}`|
