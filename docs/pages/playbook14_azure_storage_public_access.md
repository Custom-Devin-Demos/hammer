---
title: Azure Storage Public Access
keywords: playbook14
sidebar: mydoc_sidebar
permalink: playbook14_azure_storage_public_access.html
---

# Playbook 14: Azure Storage Public Access

## Introduction

This playbook describes how to configure Dow Jones Hammer to detect Azure storage accounts with blob containers that allow anonymous (public) read access. This is the Azure equivalent of [S3 buckets with public ACL](playbook1_s3_public_buckets_acl.html) / [policy](playbook5_s3_public_buckets_policy.html).

Azure checks run from the Hammer AWS control plane: identification Lambdas call Azure management APIs with the service principal stored in the `hammer-credentials` DynamoDB table (service key `azure`), and issues are stored in DynamoDB like any other Hammer issue. In this playbook, "account" means Azure **subscription id**.

## 1. Issue Identification

Dow Jones Hammer identifies those storage accounts that:
* allow public blob access on the account level (`allowBlobPublicAccess` is `true` or not set - accounts created with old API versions default to allowed), **and**
* contain at least one blob container with public access level `Blob` (anonymous read access for blobs) or `Container` (anonymous read access for container and its blobs).

Storage accounts with `allowBlobPublicAccess` set to `false` are never reported (containers listing is skipped for them), as Azure ignores container level settings in this case.

When Dow Jones Hammer detects an issue, it writes the issue to the designated DynamoDB table. Issue ID is the storage account name.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions.
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/azure-storage-public-access-identification/initiate_to_desc_azure_storage_public_access.py`|
|Identification|`hammer/identification/lambdas/azure-storage-public-access-identification/describe_azure_storage_public_access.py`|

The checker itself is implemented in `hammer/library/azure/storage.py` (`AzureStoragePublicAccessChecker`).

## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

The JIRA ticket contains cloud provider, subscription name/id, storage account name, location, resource group, storage account tags and the table with public containers and their access levels.

Additionally Dow Jones Hammer tries to detect person to report issue to by examining `owner` tag on affected storage account (`bu` and `product` tags are used the same way as for AWS resources). In case when such tag **exists** and is **valid JIRA/Slack user**:
* for JIRA: `jira_owner` parameter from [ticket_owners.json](#43-the-ticket_ownersjson-file) **is ignored** and discovered `owner` **is used instead** as a JIRA assignee;
* for Slack: discovered `owner` **is used in addition to** `slack_owner` value from [ticket_owners.json](#43-the-ticket_ownersjson-file).

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_azure_storage_public_access_issue_tickets.py
```

## 3. Issue Remediation

### 3.1 Automatic

To reduce the workload of your DevOps engineers and mitigate the threats stemming from this issue, you can configure automatic remediation of issues. It means that in case Dow Jones Hammer has detected and reported an issue, but the assignee of the report has not remediated the issue within a timeframe specified in the configuration, the Dow Jones Hammer remediation job will restrict storage account public access to eliminate this vulnerability.

In this specific case, Dow Jones Hammer will:
1. save the pre-remediation state (storage account `allowBlobPublicAccess` value and public access level of every container) as JSON to the S3 backup bucket (`aws.s3_backup_bucket` from `config.json`) under `azure_storage_public_access/<subscription id>/<storage account name>_<timestamp>.json`;
2. set public access level `None` (private) on every public container;
3. set `allowBlobPublicAccess` to `false` on the storage account.

You can use the backup to rollback the automatic remediation manually, if necessary, f.e. with Azure CLI:
```
az storage account update --resource-group <resource_group> --name <storage_account> --allow-blob-public-access true
az storage container set-permission --account-name <storage_account> --name <container> --public-access blob
```

This Python module implements the issue remediation functionality:
```
hammer/reporting-remediation/remediation/clean_azure_storage_public_access.py
```

### 3.2 Manual

To retain full control on the remediation functionality you can disable automatic remediation in [config.json](#41-the-configjson-file) and launch it manually:
1. Login to Dow Jones Hammer reporting and remediation EC2 via SSH with **centos** user and ssh key you created during [deployment](configuredeploy_overview.html#25-create-ec2-key-pair-for-hammer): `ssh -l centos -i <private_key> <EC2_IP_Address>`
2. Become **root** user: `sudo su -`
3. Change directory to Dow Jones Hammer sources: `cd /hammer-correlation-engine`
4. Launch Dow Jones Hammer remediation script: `python3.9 -m remediation.clean_azure_storage_public_access`
5. Confirm or refuse remediation of each issue separately

Use `--batch` argument to remediate all issues without confirmation (this is how the remediation cron job runs it).

## 4. Setup Instructions For This Issue

To configure the detection, reporting, and remediation of this issue, you should edit the following sections of the Dow Jones Hammer configuration files:

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
Azure subscriptions to check are listed in the `azure.accounts` section (`{"<subscription id>": "<subscription name>"}`).
To identify, report, and remediate issues of this type, you should add the following parameters in the **azure_storage_public_access** section of the **config.json** file:

|Parameter Name                |Description                                                                          |Default Value|
|------------------------------|-------------------------------------------------------------------------------------|:-----------:|
|`enabled`                     |Toggles issue detection for this issue                                               |`false`|
|`ddb.table_name`              |The name of the DynamoDB table where Dow Jones Hammer will store the identified issues of this type|`hammer-azure-storage-public-access`|
|`topic_name`                  |The name of the SNS topic used to trigger identification Lambda                      |`hammer-describe-azure-storage-public-access-lambda`|
|`accounts`                    |*Optional* comma-separated list of subscriptions to limit check for                  |`azure.accounts` from `config.json`|
|`ignore_accounts`             |*Optional* comma-separated list of subscriptions to exclude from check               |-|
|`reporting`                   |Toggle Dow Jones Hammer reporting functionality for this issue type                  |`false`|
|`remediation`                 |Toggle Dow Jones Hammer automatic remediation functionality for this issue type      |`false`|
|`remediation_accounts`        |*Optional* comma-separated list of subscriptions to remediate this issue type        |`azure.accounts` from `config.json`|
|`remediation_retention_period`|The amount of days to pass between issue detection and its automatic remediation. The value `0` denotes that Dow Jones Hammer will remediate the issue at the next remediation job run.|`21`|

Sample **config.json** section:
```
"azure": {
    "accounts": {
        "00000000-0000-0000-0000-000000000001": "azure-prod"
    }
},
"azure_storage_public_access": {
    "enabled": true,
    "ddb.table_name": "hammer-azure-storage-public-access",
    "topic_name": "hammer-describe-azure-storage-public-access-lambda",
    "reporting": true,
    "remediation": false,
    "remediation_retention_period": 21
}
```

### 4.2. The whitelist.json File

You can define exceptions to issue detection and remediation settings for specific storage accounts. To configure such exceptions, you should edit the **azure_storage_public_access** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s) |
|:----:|:-----:|
|Azure Subscription ID|Storage account names|

Sample **whitelist.json** section:
```
"azure_storage_public_access": {
    "00000000-0000-0000-0000-000000000001": ["publicwebassets", "cdnorigin"]
}
```

The **fixnow.json** file uses the same format to remediate specific storage accounts without waiting for `remediation_retention_period`.

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

### 4.4. Required Permissions

The Azure service principal (stored in the `hammer-credentials` DynamoDB table under the `azure` key as `{"tenant_id", "client_id", "client_secret"}`) needs the following permissions on every configured subscription:

|Functionality |Azure RBAC actions|Built-in role|
|--------------|------------------|-------------|
|Identification|`Microsoft.Storage/storageAccounts/read`, `Microsoft.Storage/storageAccounts/blobServices/containers/read`|`Reader`|
|Remediation   |`Microsoft.Storage/storageAccounts/write`, `Microsoft.Storage/storageAccounts/blobServices/containers/write`|`Storage Account Contributor`|

Remediation also requires `s3:PutObject` / `s3:GetObject` (HeadObject) on the S3 backup bucket for the reporting/remediation EC2 role (already granted for AWS remediation).

## 5. Logging

Dow Jones Hammer uses **CloudWatch Logs** for logging purposes.

Dow Jones Hammer automatically sets up CloudWatch Log Groups and Log Streams for this issue when you deploy Dow Jones Hammer.

### 5.1. Issue Identification Logging

Dow Jones Hammer issue identification functionality uses two Lambda functions:

* Initialization: this Lambda function selects Azure subscriptions to check for this issue as designated in the Dow Jones Hammer configuration files and triggers the check.
* Identification: this Lambda function identifies this issue for each subscription selected at the previous step.

You can see the logs for each of these Lambda functions in the following Log Groups:

|Lambda Function|CloudWatch Log Group Name                                    |
|---------------|-------------------------------------------------------------|
|Initialization |`/aws/lambda/hammer-initiate-azure-storage-public-access`    |
|Identification |`/aws/lambda/hammer-describe-azure-storage-public-access`    |

### 5.2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name                                          |
|-----------|--------------------------------------------------------------------|
|Reporting  |`reporting.create_azure_storage_public_access_issue_tickets`        |
|Remediation|`remediation.clean_azure_storage_public_access`                     |

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

|Key                |Type  |Description                                          |Example                          |
|-------------------|:----:|-----------------------------------------------------|---------------------------------|
|`provider`         |string|Cloud provider                                       |`azure`                          |
|`name`             |string|Storage account name                                 |`publicwebassets`                |
|`location`         |string|Azure location of storage account                    |`westeurope`                     |
|`resource_group`   |string|Resource group of storage account                    |`rg-web`                         |
|`resource_id`      |string|Storage account resource id                          |`/subscriptions/0000.../resourceGroups/rg-web/providers/Microsoft.Storage/storageAccounts/publicwebassets`|
|`public_containers`|map   |Public containers and their public access levels     |`{"images": "Blob", "site": "Container"}`|
|`tags`             |map   |Tags associated with storage account                 |`{"owner": "bob", "bu": "news"}` |
