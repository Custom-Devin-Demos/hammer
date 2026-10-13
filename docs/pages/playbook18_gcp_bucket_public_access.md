---
title: GCP Public Buckets
keywords: playbook18
sidebar: mydoc_sidebar
permalink: playbook18_gcp_bucket_public_access.html
---

# Playbook 18: GCP Public Buckets

## Introduction

This playbook describes how to configure Dow Jones Hammer to detect and remediate Google Cloud Storage buckets that are accessible by everyone on the Internet (`allUsers`) or by any Google account holder (`allAuthenticatedUsers`).
It is the GCP equivalent of the [S3 public buckets](playbook1_s3_public_buckets_acl.html) checks.

## 1. Issue Identification

Dow Jones Hammer identifies those buckets in the configured GCP projects that:
* have an IAM policy binding which grants any role to `allUsers` or `allAuthenticatedUsers`, **or**
* have uniform bucket-level access disabled and a legacy bucket ACL entry for `allUsers` or `allAuthenticatedUsers`.

Buckets with **public access prevention** set to `enforced` are not reported, because GCP blocks public access to them regardless of their IAM policy/ACL.

When Dow Jones Hammer detects an issue, it writes the issue to the designated DynamoDB table. The issue ID is the bucket name.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions.
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/gcp-bucket-public-access-identification/initiate_to_desc_gcp_bucket_public_access.py`|
|Identification|`hammer/identification/lambdas/gcp-bucket-public-access-identification/describe_gcp_bucket_public_access.py`|

The checker itself is implemented in `hammer/library/gcp/storage.py` (`GCPBucketsPublicAccessChecker`).

## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

The JIRA ticket contains the cloud provider, GCP project, bucket location, public IAM bindings and ACL entries, bucket labels, risk and recommendation.

Additionally Dow Jones Hammer tries to detect person to report issue to by examining `owner` label on affected bucket (`bu` and `product` labels are used the same way as AWS tags). In case when such label **exists** and is **valid JIRA/Slack user**:
* for JIRA: `jira_owner` parameter from [ticket_owners.json](#43-the-ticket_ownersjson-file) **is ignored** and discovered `owner` **is used instead** as a JIRA assignee;
* for Slack: discovered `owner` **is used in addition to** `slack_owner` value from [ticket_owners.json](#43-the-ticket_ownersjson-file).

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_gcp_bucket_public_access_issue_tickets.py
```

## 3. Issue Remediation

### 3.1 Automatic

To reduce the workload of your DevOps engineers and mitigate the threats stemming from this issue, you can configure automatic remediation of issues. It means that in case Dow Jones Hammer has detected and reported an issue, but the assignee of the report has not remediated the issue within a timeframe specified in the configuration, the Dow Jones Hammer remediation job will adjust bucket permissions to eliminate this vulnerability.

In this specific case, Dow Jones Hammer:
1. saves the current bucket IAM policy bindings and ACL to the Dow Jones Hammer S3 backup bucket (`aws.s3_backup_bucket`) as `gcp_bucket_policies/<project id>/<bucket name>_<timestamp>.json`;
2. removes `allUsers`/`allAuthenticatedUsers` members from the bucket IAM policy (bindings without other members are dropped);
3. removes `allUsers`/`allAuthenticatedUsers` entries from the legacy bucket ACL;
4. sets bucket `public_access_prevention` to `enforced` if `enforce_public_access_prevention` is `true` in configuration.

You can use the backup to restore the original bucket permissions with `gsutil iam set` / `gcloud storage buckets set-iam-policy` if necessary.

This Python module implements the issue remediation functionality:
```
hammer/reporting-remediation/remediation/clean_gcp_bucket_public_access.py
```

### 3.2 Manual

To manually remediate issues of this type, run the remediation module from the Dow Jones Hammer reporting/remediation EC2 instance:
```
cd /hammer-correlation-engine && python3.9 -m remediation.clean_gcp_bucket_public_access
```
(use the Python interpreter configured in `cronjobs.python`).
Dow Jones Hammer asks for confirmation before remediating each bucket. Use the `--batch` option to skip confirmations.

### 3.3 Required permissions

The GCP service account (stored under the `gcp` key in the `hammer-credentials` DynamoDB table) needs the following permissions in each checked project:

|Purpose       |Permissions|
|--------------|-----------|
|Identification|`storage.buckets.list`, `storage.buckets.get`, `storage.buckets.getIamPolicy`|
|Remediation   |`storage.buckets.setIamPolicy`, `storage.buckets.update`|

For example, the predefined role `roles/storage.admin` covers both, or create a custom role with the permissions above.

## 4. Setup Instructions For This Issue

To configure the detection, reporting, and remediation of this issue, you should edit the following sections of the Dow Jones Hammer configuration files:

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
To identify, report, and remediate issues of this type, you should add the following parameters in the **gcp_bucket_public_access** section of the **config.json** file:

|Parameter Name                    |Description                                                                     |Default Value|
|----------------------------------|--------------------------------------------------------------------------------|:-----------:|
|`enabled`                         |Toggles issue detection for this issue                                          |`false`|
|`ddb.table_name`                  |The name of the DynamoDB table to which Dow Jones Hammer would record detected issues of this type|`hammer-gcp-bucket-public-access`|
|`topic_name`                      |The name of the SNS topic used to trigger identification Lambda                |`hammer-describe-gcp-bucket-public-access-lambda`|
|`accounts`                        |*Optional* list of GCP project ids to limit check for                           |`gcp.accounts` from `config.json`|
|`ignore_accounts`                 |*Optional* list of GCP project ids to exclude from check                        |`[]`|
|`reporting`                       |Toggle Dow Jones Hammer reporting functionality for this issue                  |`false`|
|`remediation`                     |Toggle Dow Jones Hammer automatic remediation functionality for this issue      |`false`|
|`remediation_accounts`            |*Optional* list of GCP project ids to limit remediation for                     |`accounts`|
|`remediation_retention_period`    |The amount of days to pass between issue detection and its automatic remediation|`21`|
|`enforce_public_access_prevention`|Set bucket `public_access_prevention` to `enforced` during remediation          |`false`|

Projects are defined in the **gcp** section of **config.json**:
```
"gcp": {
    "accounts": {
        "my-gcp-project": "production project"
    }
}
```

Sample **config.json** section:
```
"gcp_bucket_public_access": {
    "enabled": true,
    "ddb.table_name": "hammer-gcp-bucket-public-access",
    "topic_name": "hammer-describe-gcp-bucket-public-access-lambda",
    "enforce_public_access_prevention": false,
    "reporting": true,
    "remediation": false,
    "remediation_retention_period": 21
}
```

### 4.2. The whitelist.json File

You can define exceptions to issue detection settings for specific buckets. To configure such exceptions, you should edit the **gcp_bucket_public_access** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s) |
|:----:|:-----:|
|GCP Project ID|Bucket names|

Sample **whitelist.json** section:
```
"gcp_bucket_public_access": {
    "my-gcp-project": ["public-website-assets", "public-downloads"]
}
```

### 4.3. The ticket_owners.json File

You should use the **ticket_owners.json** file to configure the integration of Dow Jones Hammer with JIRA and/or Slack for issue reporting purposes.

You can configure these parameters for specific GCP projects (use project id as account key) and globally. Project-specific settings precede the global settings in the **ticket_owners.json** configuration file.

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

|Lambda Function|CloudWatch Log Group Name                               |
|---------------|--------------------------------------------------------|
|Initialization |`/aws/lambda/hammer-initiate-gcp-bucket-public-access`  |
|Identification |`/aws/lambda/hammer-describe-gcp-bucket-public-access`  |

### 5.2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name                                      |
|-----------|----------------------------------------------------------------|
|Reporting  |`reporting.create_gcp_bucket_public_access_issue_tickets`       |
|Remediation|`remediation.clean_gcp_bucket_public_access`                    |

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

|Key                          |Type   |Description                                                  |Example                          |
|-----------------------------|:-----:|-------------------------------------------------------------|---------------------------------|
|`provider`                   |string |Cloud provider                                               |`gcp`                            |
|`name`                       |string |Bucket name                                                  |`my-public-bucket`               |
|`location`                   |string |Bucket location                                              |`US`                             |
|`public_bindings`            |map    |Public IAM policy bindings `{role: [members]}`               |`{"roles/storage.objectViewer": ["allUsers"]}`|
|`public_acls`                |map    |Public legacy ACL entries `{entity: [roles]}`                |`{"allUsers": ["READER"]}`       |
|`uniform_bucket_level_access`|boolean|If uniform bucket-level access is enabled                    |`false`                          |
|`public_access_prevention`   |string |Bucket public access prevention setting                      |`inherited`                      |
|`owner`                      |string |Value of `owner` bucket label                                |`alice`                          |
|`tags`                       |map    |Labels associated with bucket                                |`{"owner": "alice", "bu": "news"}`|
