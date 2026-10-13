---
title: Azure Storage Account Keys Rotation
keywords: playbook17
sidebar: mydoc_sidebar
permalink: playbook17_azure_storage_keys_rotation.html
---

# Playbook 17: Azure Storage Account Keys Rotation

## Introduction

This playbook describes how to configure Dow Jones Hammer to detect Azure storage accounts with shared access keys (`key1`/`key2`) that have not been rotated for a defined number of days. Storage account access keys grant full access to all data in the storage account, so they are handled the same way as [IAM user keys rotation](playbook4_keysrotation.html) in AWS.


## 1. Issue Identification

Dow Jones Hammer checks the `keyCreationTime` property of every storage account in each configured Azure subscription. A storage account is reported when **shared key access is allowed** (`allowSharedKeyAccess` is `true` or not set) and at least one of its access keys:
* was created (or last regenerated) earlier than `rotation_criteria_days` ago, or
* has unknown creation time (`keyCreationTime` is empty - Azure did not track key creation time for keys which have not been regenerated since the property was introduced).

Storage accounts with shared key access disabled (`allowSharedKeyAccess` is `false`) are not reported, as their keys can not be used.

The issue id is the storage account name (it is unique across Azure).

When Dow Jones Hammer detects an issue, it writes the issue to the designated DynamoDB table.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions.
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/azure-storage-keys-rotation-identification/initiate_to_desc_azure_storage_keys_rotation.py`|
|Identification|`hammer/identification/lambdas/azure-storage-keys-rotation-identification/describe_azure_storage_keys_rotation.py`|

The checking logic is implemented in `hammer/library/azure/storage_keys.py`.


## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

Additionally Dow Jones Hammer tries to detect person to report issue to by examining `owner` tag on affected storage account. In case when such tag **exists** and is **valid JIRA/Slack user**:
* for JIRA: `jira_owner` parameter from [ticket_owners.json](#43-the-ticket_ownersjson-file) **is ignored** and discovered `owner` **is used instead** as a JIRA assignee;
* for Slack: discovered `owner` **is used in addition to** `slack_owner` value from [ticket_owners.json](#43-the-ticket_ownersjson-file).

`bu` and `product` tags are used the same way as for AWS resources.

The JIRA ticket contains cloud provider, subscription name/id, storage account name, location, resource group, a table with stale keys and their creation time, storage account tags, risk and recommendation.

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_azure_storage_keys_rotation_issue_tickets.py
```


## 3. Issue Remediation

### 3.1 Automatic

To reduce the workload of your DevOps engineers and mitigate the threats stemming from this issue, you can configure automatic remediation of issues. It means that in case Dow Jones Hammer has detected and reported an issue, but the assignee of the report has not remediated the issue within a timeframe specified in the configuration file, the Dow Jones Hammer remediation job will regenerate the stale access key(s) of the storage account.

**Note**: regenerating a key immediately invalidates it, so applications (and SAS tokens signed with this key) which still use the stale key **will lose access** to the storage account. Make sure owners switched their applications to the other key or to Azure AD authorization before the remediation date.

Regenerated keys can not be restored, so there is no rollback for this remediation: applications must be reconfigured with the new key.

This Python module implements the issue remediation functionality:
```
hammer/reporting-remediation/remediation/clean_azure_storage_keys_rotation.py
```

### 3.2 Manual

To retain full control on the remediation functionality you can disable automatic remediation in [config.json](#41-the-configjson-file) and launch it manually:
1. Login to Dow Jones Hammer reporting and remediation EC2 via SSH with **centos** user and ssh key you created during [deployment](configuredeploy_overview.html#25-create-ec2-key-pair-for-hammer): `ssh -l centos -i <private_key> <EC2_IP_Address>`
2. Become **root** user: `sudo su -`
3. Change directory to Dow Jones Hammer sources: `cd /hammer-correlation-engine`
4. Launch Dow Jones Hammer remediation script: `python3.9 -m remediation.clean_azure_storage_keys_rotation`
5. Confirm or refuse remediation of each issue separately


## 4. Setup Instructions For This Issue

To configure the detection, reporting, and remediation of this issue, you should edit the following sections of the Dow Jones Hammer configuration files.

Azure service principal credentials (`tenant_id`, `client_id`, `client_secret`) are stored in the `hammer-credentials` DynamoDB table under the `azure` key and subscriptions to check are listed in the `azure.accounts` section of **config.json**.

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
To identify, report, and remediate issues of this type, you should add the following parameters in the **azure_storage_keys_rotation** section of the **config.json** file:

|Parameter Name                |Description                            | Default Value|
|------------------------------|---------------------------------------|:------------:|
|`enabled`                     |Toggles issue detection for this issue |`false`       |
|`ddb.table_name`              |Name of the DynamoDB table where Dow Jones Hammer will store the identified issues of this type| `hammer-azure-storage-keys-rotation`|
|`topic_name`                  |Name of the SNS topic used to trigger identification lambda | `hammer-describe-azure-storage-keys-rotation-lambda`|
|`accounts`                    |*Optional* list of subscription ids to check and report for this issue type | **azure.accounts** from config.json |
|`remediation_accounts`        |*Optional* list of subscription ids to remediate this issue type            | **azure.accounts** from config.json |
|`rotation_criteria_days`      |The threshold number of days passed since the key creation (last regeneration)|`90`|
|`reporting`                   |Toggle Dow Jones Hammer reporting functionality for this issue type    |`false`|
|`remediation`                 |Toggle Dow Jones Hammer automatic remediation functionality for this issue type |`false`|
|`remediation_retention_period`|The amount of days to pass between issue detection and its automatic remediation. The value `0` denotes that Dow Jones Hammer will remediate the issue at the next remediation job run.|`7`|

Sample **config.json** section:
```
"azure_storage_keys_rotation": {
    "enabled": true,
    "ddb.table_name": "hammer-azure-storage-keys-rotation",
    "topic_name": "hammer-describe-azure-storage-keys-rotation-lambda",
    "rotation_criteria_days": 90,
    "reporting": true,
    "remediation": false,
    "remediation_retention_period": 7
}
```

### 4.2. The whitelist.json File

You can define exceptions to issue detection settings for specific storage accounts. To configure such exceptions, you should edit the **azure_storage_keys_rotation** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s) |
|:----:|:-----:|
|Azure Subscription ID|Storage account names|

Sample **whitelist.json** section:
```
"azure_storage_keys_rotation": {
    "00000000-0000-0000-0000-000000000001": ["legacyappstorage", "sharedlogsstorage"]
}
```

### 4.3. The ticket_owners.json File

You should use the **ticket_owners.json** file to configure the integration of Dow Jones Hammer with JIRA and/or Slack for issue reporting purposes.

You can configure these parameters for specific Azure subscriptions (keyed by subscription id in the `account` section) and globally. Subscription-specific settings precede the global settings in the **ticket_owners.json** configuration file.

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
        "00000000-0000-0000-0000-000000000001": {
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

The Dow Jones Hammer service principal needs the following permissions in each configured subscription:

|Designation   |Permission                                              |Built-in role example|
|--------------|--------------------------------------------------------|---------------------|
|Identification|`Microsoft.Storage/storageAccounts/read`                |`Reader`             |
|Remediation   |`Microsoft.Storage/storageAccounts/regeneratekey/action`|`Storage Account Key Operator Service Role`|

Identification does not need `listKeys` permission: key values are never read by Dow Jones Hammer, only their creation time.


## 5. Logging

Dow Jones Hammer uses **CloudWatch Logs** for logging purposes.

Dow Jones Hammer automatically sets up CloudWatch Log Groups and Log Streams for this issue when you deploy Dow Jones Hammer.

### 5.1. Issue Identification Logging

Dow Jones Hammer issue identification functionality uses two Lambda functions:

* Initialization: this Lambda function selects Azure subscriptions to check for this issue as designated in the Dow Jones Hammer configuration files and triggers the check.
* Identification: this Lambda function identifies this issue for each subscription selected at the previous step.

You can see the logs for each of these Lambda functions in the following Log Groups:

|Lambda Function|CloudWatch Log Group Name                                  |
|---------------|-----------------------------------------------------------|
|Initialization |`/aws/lambda/hammer-initiate-azure-storage-keys-rotation`  |
|Identification |`/aws/lambda/hammer-describe-azure-storage-keys-rotation`  |

### 5.2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name                                          |
|-----------|--------------------------------------------------------------------|
|Reporting  |`reporting.create_azure_storage_keys_rotation_issue_tickets`        |
|Remediation|`remediation.clean_azure_storage_keys_rotation`                     |

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

|Key             |Type  |Description                                                |Example                          |
|----------------|:----:|-----------------------------------------------------------|---------------------------------|
|`provider`      |string|Cloud provider                                             |`azure`                          |
|`id`            |string|Storage account resource id                                |`/subscriptions/0000.../resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/appstorage`|
|`name`          |string|Storage account name                                       |`appstorage`                     |
|`location`      |string|Azure location of storage account                          |`westeurope`                     |
|`resource_group`|string|Resource group of storage account                          |`rg-app`                         |
|`keys`          |map   |Stale access keys with creation time (`null` if unknown)   |`{"key1": "2025-01-10T08:00:00+00:00", "key2": null}`|
|`tags`          |map   |Tags associated with storage account                       |`{"owner": "alice", "bu": "news"}`|
