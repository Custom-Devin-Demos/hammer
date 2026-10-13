---
title: GCP Unencrypted Disks
keywords: playbook20
sidebar: mydoc_sidebar
permalink: playbook20_gcp_unencrypted_disks.html
---

# Playbook 20: GCP Unencrypted Disks

## Introduction

This playbook describes how to configure Dow Jones Hammer to detect Google Cloud Compute Engine persistent disks that are encrypted only with Google-managed keys, i.e. disks not protected with a customer-managed encryption key (CMEK) from Cloud KMS or a customer-supplied encryption key (CSEK). This is the GCP equivalent of [EBS Unencrypted Volumes](playbook7_ebs_unencrypted_volumes.html).


## 1. Issue Identification

Dow Jones Hammer lists all zonal and regional persistent disks in every configured GCP project (`disks.aggregatedList` API) and identifies those disks which have:
* no `diskEncryptionKey.kmsKeyName` (not encrypted with CMEK), **and**
* no customer-supplied key (`diskEncryptionKey.sha256`/`rawKey`/`rsaEncryptedKey` are empty).

Each issue is identified by `{zone}/{disk name}` (for regional disks the region is used instead of the zone, f.e. `us-central1/my-regional-disk`).

When Dow Jones Hammer detects an issue, it writes the issue to the designated DynamoDB table. Issues for disks which were deleted or recreated with CMEK/CSEK are marked as resolved during the next check.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions (running in Hammer's AWS account).
GCP APIs are global per project, so one identification Lambda invocation checks one project (no region chaining).
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/gcp-disk-unencrypted-identification/initiate_to_desc_gcp_unencrypted_disks.py`|
|Identification|`hammer/identification/lambdas/gcp-disk-unencrypted-identification/describe_gcp_unencrypted_disks.py`|
|Library       |`hammer/library/gcp/compute.py`|


## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

The JIRA ticket contains the cloud provider, GCP project name/ID, disk location, disk details (status, type, size, encryption type, attached instances), disk labels, risk and recommendation.

Additionally Dow Jones Hammer tries to detect person to report issue to by examining `owner` label on affected disk (`bu` and `product` labels are used in the same way as AWS tags). In case when such label **exists** and is **valid JIRA/Slack user**:
* for JIRA: `jira_owner` parameter from [ticket_owners.json](#43-the-ticket_ownersjson-file) **is ignored** and discovered `owner` **is used instead** as a JIRA assignee;
* for Slack: discovered `owner` **is used in addition to** `slack_owner` value from [ticket_owners.json](#43-the-ticket_ownersjson-file).

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_gcp_unencrypted_disk_issue_tickets.py
```

## 3. Issue Remediation

In this specific case, automated remediation **is not available**: GCP does not allow changing the encryption key of an existing disk.
To fix the issue, create a snapshot of the disk and create a new disk from it using a Cloud KMS key, f.e.:
```
gcloud compute snapshots create my-disk-snapshot --source-disk=my-disk --source-disk-zone=us-central1-a
gcloud compute disks create my-disk-cmek --zone=us-central1-a --source-snapshot=my-disk-snapshot \
    --kms-key=projects/KMS_PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY
```

## 4. Setup Instructions For This Issue

To configure the detection, reporting, and remediation of this issue, you should edit the following sections of the Dow Jones Hammer configuration files:

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
GCP projects to check are configured in the `accounts` parameter of the **gcp** section (`{"project id": "project name"}`); the service account JSON key is stored in the `hammer-credentials` DynamoDB table under the `gcp` key (never in **config.json**).
To identify and report issues of this type, you should add the following parameters in the **gcp_disk_unencrypted** section of the **config.json** file:

|Parameter Name  |Description                                                                                     |Default Value|
|----------------|------------------------------------------------------------------------------------------------|:-----------:|
|`enabled`       |Toggles issue detection for this issue                                                          |`false`      |
|`ddb.table_name`|The name of the DynamoDB table to which Dow Jones Hammer would record detected issues of this type|`hammer-gcp-disks-unencrypted`|
|`topic_name`    |The name of the SNS topic used to trigger identification Lambda                                 |`hammer-describe-gcp-unencrypted-disks-lambda`|
|`accounts`      |*Optional* comma-separated list of GCP project ids to limit check for                           |`gcp.accounts` from `config.json`|
|`ignore_accounts`|*Optional* comma-separated list of GCP project ids to exclude from check                       |`[]`|
|`reporting`     |Toggle Dow Jones Hammer reporting functionality for this issue                                  |`false`      |

Sample **config.json** sections:
```
"gcp": {
    "accounts": {
        "my-gcp-project": "gcp-prod"
    }
},
"gcp_disk_unencrypted": {
    "enabled": true,
    "ddb.table_name": "hammer-gcp-disks-unencrypted",
    "topic_name": "hammer-describe-gcp-unencrypted-disks-lambda",
    "accounts": ["my-gcp-project"],
    "reporting": true,
    "remediation": false
}
```

### 4.2. The whitelist.json File

You can define exceptions to issue detection settings for specific disks. To configure such exceptions, you should edit the **gcp_disk_unencrypted** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s) |
|:----:|:-----:|
|GCP Project ID|Disk IDs in `{zone}/{disk name}` format|

Sample **whitelist.json** section:
```
"gcp_disk_unencrypted": {
    "my-gcp-project": ["us-central1-a/scratch-disk", "us-central1/regional-disk"]
}
```

### 4.3. The ticket_owners.json File

You should use the **ticket_owners.json** file to configure the integration of Dow Jones Hammer with JIRA and/or Slack for issue reporting purposes.

You can configure these parameters for specific GCP projects (using project id as the account key) and globally. Account-specific settings precede the global settings in the **ticket_owners.json** configuration file.

Check the following table for parameters:

|Parameter Name       |Description                                                         |Sample Value     |
|---------------------|--------------------------------------------------------------------|:---------------:|
|`jira_project`       |The name of the JIRA project where Dow Jones Hammer will create the issue     | `AWSSEC`        |
|`jira_owner`         |The name of the JIRA user to whom Dow Jones Hammer will assign the issue      | `Support-Cloud` |
|`jira_parent_ticket` |The JIRA ticket to which Dow Jones Hammer will link the new ticket it creates | `AWSSEC-1234`   |
|`slack_owner`        |Name(s) of the Slack channels (prefixed by `#`) and/or Slack users that will receive issue reports from Dow Jones Hammer | `["#devops-channel", "bob"]` |

Sample **ticket_owners.json** section:

Account-specific settings:
```
{
    "account": {
        "my-gcp-project": {
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

### 4.4. Required GCP permissions

The Hammer service account needs the following permission in every checked project:

|Permission          |Used for                                     |
|--------------------|---------------------------------------------|
|`compute.disks.list`|Listing zonal and regional disks (`disks.aggregatedList`)|

The predefined `roles/compute.viewer` role (or a custom role with the permission above) is sufficient.

## 5. Logging

Dow Jones Hammer uses **CloudWatch Logs** for logging purposes.

Dow Jones Hammer automatically sets up CloudWatch Log Groups and Log Streams for this issue when you deploy Dow Jones Hammer.

### 5.1. Issue Identification Logging

Dow Jones Hammer issue identification functionality uses two Lambda functions:

* Initialization: this Lambda function selects GCP projects to check for this issue as designated in the Dow Jones Hammer configuration files and triggers the check.
* Identification: this Lambda function identifies this issue for each project selected at the previous step.

You can see the logs for each of these Lambda functions in the following Log Groups:

|Lambda Function|CloudWatch Log Group Name                           |
|---------------|----------------------------------------------------|
|Initialization |`/aws/lambda/hammer-initiate-gcp-unencrypted-disks` |
|Identification |`/aws/lambda/hammer-describe-gcp-unencrypted-disks` |

### 5.2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name                                  |
|-----------|------------------------------------------------------------|
|Reporting  |`reporting.create_gcp_unencrypted_disk_issue_tickets`       |

### 5.3. Slack Reports

In case you have enabled Dow Jones Hammer and Slack integration, Dow Jones Hammer sends notifications about issue identification to the designated Slack channel and/or recipient(s).

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
|`provider`   |string|Cloud provider                                             |`gcp`                            |
|`name`       |string|Disk name                                                  |`my-test-disk`                   |
|`location`   |string|Zone (or region for regional disks) where disk exists      |`us-central1-a`                  |
|`status`     |string|Disk status                                                |`READY`                          |
|`disk_type`  |string|Disk type                                                  |`pd-standard`                    |
|`size_gb`    |number|Disk size in GB                                            |`10`                             |
|`encryption` |string|Disk encryption type                                       |`google-managed`                 |
|`users`      |list  |Names of instances the disk is attached to                 |`["instance-1"]`                 |
|`tags`       |map   |Labels associated with disk                                |`{"owner": "alice", "bu": "news"}`|
