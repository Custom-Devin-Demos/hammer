---
title: GCP Service Account Keys Rotation
keywords: playbook21
sidebar: mydoc_sidebar
permalink: playbook21_gcp_sa_keys_rotation.html
---

# Playbook 21: GCP Service Account Keys Rotation

## Introduction

This playbook describes how to configure Dow Jones Hammer to detect user-managed GCP service account keys that were created earlier than the threshold value (keys that have not been rotated). It is the GCP equivalent of [IAM User Key Rotation](playbook4_keysrotation.html).

User-managed service account keys are long-lived credentials: when such a key leaks (committed to a repository, left on a laptop, exposed in logs), anyone holding it can act as the service account until the key is disabled or deleted. Regular rotation reduces this window.


## 1. Issue Identification

For every GCP project listed in the [gcp section](editconfig.html) of the configuration, Dow Jones Hammer lists all service accounts and their **user-managed** keys (Google-managed `SYSTEM_MANAGED` keys are rotated by Google and are not checked).
A key is reported when it is **enabled** and its ```valid_after_time``` (key creation time) is older than ```rotation_criteria_days``` days. Disabled keys are not reported.

When Dow Jones Hammer detects an issue, it writes the issue to the designated DynamoDB table. The issue id is the key resource name (`projects/<project>/serviceAccounts/<email>/keys/<key id>`).
Issues for keys that were deleted, disabled or are no longer stale are marked as resolved during the next identification run.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions.
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/gcp-sa-keys-rotation-identification/initiate_to_desc_gcp_sa_keys_rotation.py`|
|Identification|`hammer/identification/lambdas/gcp-sa-keys-rotation-identification/describe_gcp_sa_keys_rotation.py`|

The checks are implemented in `hammer/library/gcp/iam.py` (`GCPServiceAccountKeyChecker`).


## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

GCP service accounts do not support labels, so the ticket owner is taken from [ticket_owners.json](#43-the-ticket_ownersjson-file) (keyed by GCP project id).

The JIRA ticket contains the cloud provider, project name/id, service account, key id, key resource name, creation time, key age, expiration time, risk and recommendation.

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_gcp_sa_keys_rotation_issue_tickets.py
```


## 3. Issue Remediation

### 3.1 Automatic

To reduce the workload of your DevOps engineers and mitigate the threats stemming from this issue, you can configure automatic remediation of issues. It means that in case Dow Jones Hammer has detected and reported an issue, but the assignee of the report has not remediated the issue within a timeframe specified in the configuration file, the Dow Jones Hammer remediation job will disable the stale key.

In this specific case, Dow Jones Hammer will **disable** the detected service account key(s) (`projects.serviceAccounts.keys.disable`). The key is not deleted, so it can't be used for authentication to GCP, but it can be re-enabled if required.

Before remediation Dow Jones Hammer checks that the key still exists and is enabled; whitelisted keys/service accounts, not reported issues and issues reported less than `remediation_retention_period` days ago (unless listed in **fixnow.json**) are skipped.

To rollback automatic remediation, re-enable the key:
```
gcloud iam service-accounts keys enable <key id> --iam-account=<service account email> --project=<project id>
```

This Python module implements the issue remediation functionality:
```
hammer/reporting-remediation/remediation/clean_gcp_sa_keys_rotation.py
```

### 3.2 Manual

To retain full control on the remediation functionality you can disable automatic remediation in [config.json](#41-the-configjson-file) and launch it manually:
1. Login to Dow Jones Hammer reporting and remediation EC2 via SSH with **centos** user and ssh key you created during [deployment](configuredeploy_overview.html#25-create-ec2-key-pair-for-hammer): `ssh -l centos -i <private_key> <EC2_IP_Address>`
2. Become **root** user: `sudo su -`
3. Change directory to Dow Jones Hammer sources: `cd /hammer-correlation-engine`
4. Launch Dow Jones Hammer remediation script: `python3.9 -m remediation.clean_gcp_sa_keys_rotation`
5. Confirm or refuse remediation of each issue separately


## 4. Setup Instructions For This Issue

The GCP service account used by Dow Jones Hammer is stored in the `hammer-credentials` DynamoDB table under the `gcp` key (see [prerequisites](prerequisites.html)). It requires the following permissions in each checked project:

|Designation   |Permissions                                                                 |Predefined role |
|--------------|----------------------------------------------------------------------------|----------------|
|Identification|`iam.serviceAccounts.list`, `iam.serviceAccountKeys.list`                   |`roles/iam.securityReviewer` (or `roles/iam.serviceAccountKeyAdmin`)|
|Remediation   |`iam.serviceAccountKeys.get`, `iam.serviceAccountKeys.disable`              |`roles/iam.serviceAccountKeyAdmin`|

To configure the detection, reporting, and remediation of this issue, you should edit the following sections of the Dow Jones Hammer configuration files:

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
To identify, report, and remediate issues of this type, you should add the following parameters in the **gcp_sa_keys_rotation** section of the **config.json** file:

|Parameter Name                |Description                            | Default Value|
|------------------------------|---------------------------------------|:------------:|
|`enabled`                     |Toggles issue detection for this issue (also requires enabled `gcp` section) |`true`        |
|`ddb.table_name`              |Name of the DynamoDB table where Dow Jones Hammer will store the identified issues of this type| `hammer-gcp-sa-keys-rotation`|
|`topic_name`                  |Name of the SNS topic used to trigger identification lambda | `hammer-describe-gcp-sa-keys-rotation-lambda`|
|`accounts`                    |*Optional* comma-separated list of GCP project ids to check and report for this issue type | **gcp.accounts** from config.json |
|`ignore_accounts`             |*Optional* comma-separated list of GCP project ids to exclude from check | `[]` |
|`remediation_accounts`        |*Optional* comma-separated list of GCP project ids to remediate this issue type | **gcp.accounts** from config.json |
|`rotation_criteria_days`      |The threshold number of days passed since key creation |`90`|
|`reporting`                   |Toggle Dow Jones Hammer reporting functionality for this issue type    |`false`|
|`remediation`                 |Toggle Dow Jones Hammer automatic remediation functionality for this issue type |`false`|
|`remediation_retention_period`|The amount of days to pass between issue detection and its automatic remediation. The value `0` denotes that Dow Jones Hammer will remediate the issue at the next remediation job run.|`365`|

Sample **config.json** section:

```
"gcp": {
    "enabled": true,
    "accounts": {
        "my-gcp-project": "production project"
    }
},
"gcp_sa_keys_rotation": {
    "enabled": true,
    "ddb.table_name": "hammer-gcp-sa-keys-rotation",
    "topic_name": "hammer-describe-gcp-sa-keys-rotation-lambda",
    "rotation_criteria_days": 90,
    "reporting": false,
    "remediation": false,
    "remediation_retention_period": 7
}
```

### 4.2. The whitelist.json File

You can define exceptions to issue detection and remediation settings for specific service accounts or keys. To configure such exceptions, you should edit the **gcp_sa_keys_rotation** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s) |
|:----:|:-----:|
|GCP project id|Service account emails or key resource names|

Sample **whitelist.json** section:

```
"gcp_sa_keys_rotation": {
    "my-gcp-project": ["legacy-app@my-gcp-project.iam.gserviceaccount.com",
                       "projects/my-gcp-project/serviceAccounts/ci@my-gcp-project.iam.gserviceaccount.com/keys/1a2b3c4d5e6f"]
}
```

### 4.3. The ticket_owners.json File

You should use the **ticket_owners.json** file to configure the integration of Dow Jones Hammer with JIRA and/or Slack for issue reporting purposes.

You can configure these parameters for specific GCP projects (by project id) and globally. Project-specific settings precede the global settings in the **ticket_owners.json** configuration file.

Check the following table for parameters:

|Parameter Name       |Description                                                         |Sample Value     |
|---------------------|--------------------------------------------------------------------|:---------------:|
|`jira_project`       |The name of the JIRA project where Dow Jones Hammer will create the issue     | `AWSSEC`        |
|`jira_owner`         |The name of the JIRA user to whom Dow Jones Hammer will assign the issue      | `Support-Cloud` |
|`jira_parent_ticket` |The JIRA ticket to which Dow Jones Hammer will link the new ticket it creates | `AWSSEC-1234`   |
|`slack_owner`        |Name(s) of the Slack channels (prefixed by `#`) and/or Slack users that will receive issue reports from Dow Jones Hammer | `["#devops-channel", "bob"]` |

Sample **ticket_owners.json** section:

Project-specific settings:
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

## 5. Logging

Dow Jones Hammer uses **CloudWatch Logs** for logging purposes.

Dow Jones Hammer automatically sets up CloudWatch Log Groups and Log Streams for this issue when you deploy Dow Jones Hammer.

### 5.1. Issue Identification Logging

Dow Jones Hammer issue identification functionality uses two Lambda functions:

* Initialization: this Lambda function selects GCP projects to check for this issue as designated in the Dow Jones Hammer configuration files and triggers the check.
* Identification: this Lambda function identifies this issue for each project selected at the previous step.

You can see the logs for each of these Lambda functions in the following Log Groups:

|Lambda Function|CloudWatch Log Group Name                          |
|---------------|---------------------------------------------------|
|Initialization |`/aws/lambda/hammer-initiate-gcp-sa-keys-rotation` |
|Identification |`/aws/lambda/hammer-describe-gcp-sa-keys-rotation` |

### 5.2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name                                 |
|-----------|-----------------------------------------------------------|
|Reporting  |`reporting.create_gcp_sa_keys_rotation_issue_tickets`      |
|Remediation|`remediation.clean_gcp_sa_keys_rotation`                   |

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

|Key                           |Type  |Description                                                   |Example                    |
|------------------------------|:----:|--------------------------------------------------------------|---------------------------|
|`provider`                    |string|Cloud provider                                                |`gcp`                      |
|`name`                        |string|Service account email and key id                              |`app@my-gcp-project.iam.gserviceaccount.com/1a2b3c4d5e6f`|
|`location`                    |string|Resource location (service accounts are global)               |`global`                   |
|`tags`                        |map   |Resource labels (always empty, service accounts do not support labels)|`{}`               |
|`service_account`             |string|Service account email                                         |`app@my-gcp-project.iam.gserviceaccount.com`|
|`service_account_display_name`|string|Service account display name                                  |`app`                      |
|`key_id`                      |string|Service account key id                                        |`1a2b3c4d5e6f`             |
|`created`                     |string|Key creation time (`valid_after_time`) in ISO 8601 format     |`2018-02-14T16:48:02+00:00`|
|`expires`                     |string|Key expiration time (`valid_before_time`) in ISO 8601 format, `null` if key never expires|`null`|
