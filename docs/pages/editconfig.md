---
title: Configuration Files
keywords: Configuration Files
sidebar: mydoc_sidebar
permalink: editconfig.html
---

Samples of Dow Jones Hammer configuration files are available at `deployment/configs/`.

There are three configuration files for Dow Jones Hammer:
* `deployment/configs/config.json` - this is the main configuration file for Dow Jones Hammer;
* `deployment/configs/ticket_owners.json` - this configuration file contains more specific settings for JIRA integration;
* `deployment/configs/whitelist.json` - this configuration file describes issues, that you have to override before Dow Jones Hammer will scan your AWS landscape.

## 1. Configure General Dow Jones Hammer Configuration Parameters

### 1.1. Master AWS Account Settings

You should add the following settings to the **aws** section of the `config.json` configuration file to define Dow Jones Hammer deployment specifics.

**Required keys**
* **main_account_id**: the ID of the master AWS account where you will deploy Dow Jones Hammer;
* **region**: the region of the master AWS account where you will deploy Dow Jones Hammer. This value is used only as a fallback when automatic detection of AWS deployment region is failed;
* **role_name_identification**: name of the IAM cross-account role for the issues identification functionality. **Make sure** the value of this parameter matches the value you've used for `LambdaIAMCrossAccountRole` when deploying [IAM Cross-account Identification Role](deployment_cloudformation.html#411-iam-cross-account-identification-role);
* **role_name_reporting**: name of the IAM cross-account role for the issues reporting and remediation functionality. **Make sure** the value of this parameter matches the value you've used for `EC2IAMCrossAccountRole` when deploying [IAM Cross-account Reporting/Remediation Role](deployment_cloudformation.html#412-iam-cross-account-reportingremediation-role);
* **accounts**: IDs of slave AWS accounts that Dow Jones Hammer will check. In case you want Dow Jones Hammer to check master account - add master account ID here as well;
* **s3_backup_bucket**: name of the [pre-created](configuredeploy_overview.html#24-create-s3-buckets-for-hammer) S3 backup bucket for the [remediation rollback functionality](remediation_backup_rollback.html).


**Optional keys**:
* **regions**: limits checks to only specified regions. In case you have not specified this key, Dow Jones Hammer will check in the slave accounts the same list of regions as in the Dow Jones Hammer master account. In case you have specified the key, but with an empty value, Dow Jones Hammer will check **no regions** in the slave account(s) at all;
* **ddb_backup**: configures setting for the DynamoDB tables backup:
    * **enabled**: enables/disables DynamoDB table backup. The default value is `false`;
    * **retention_days**: sets the retention period for DynamoDB table backup. The default value is `7` days.

Configuration example:
```
"aws": {
    "main_account_id": "123456789012",
    "region": "eu-west-1",
    "role_name_identification": "hammer-cloudsec-crossact-id",
    "role_name_reporting": "hammer-cloudsec-crossact-ec2",
    "accounts": {
        "123456789012": "master",
        "210987654321": "slave1"
    },
    "s3_backup_bucket": "hammer-backup-bucket",
    "ddb_backup": {
        "enabled": true,
        "retention_days": 7
    }
}
```

### 1.2. Scheduling Settings

You can configure the scheduling parameters for reporting and remediation jobs to occur. **This is an optional step**.

The **cronjobs** section of the `config.json` file defines how periodically reporting and remediation jobs will run.
Please use the standard **crontab** syntax to define the timing of these jobs' runs.

Configuration example:
```
"cronjobs": {
    "reporting": "5 * * * *",
    "remediation": "30 10 * * *",
    "python": "python3.6"
}
```

The optional **python** key defines the Python interpreter used by reporting and remediation cron jobs (and by the Slack bot service) on the reporting/remediation EC2. The default value is `python3.6`. Set it to `python3.9` if you enable any [Azure/GCP](multicloud_overview.html) issue type, because Azure/GCP SDKs require Python 3.8 or newer. The reporting/remediation EC2 has both `python3.6` and `python3.9` installed and reads this key on every (re)start.

**Note**: the default frequency of identification Lambda function runs is `once an hour`. To decrease this frequency please use:
* the CloudFormation parameter [IdentificationCheckRateExpression](deployment_cloudformation.html#313-identification-functionality);
* the Terraform variable [identificationCheckRateExpression](deployment_terraform.html#32-the-variablestf-file).

### 1.3. Reporting Setup (JIRA/Slack)
The following sections define the integration of Dow Jones Hammer with JIRA and/or Slack for reporting purposes. As soon as this step is optional, you can configure one integration, both, or none.

**Note**: for JIRA or Slack integration to be functional, **after** successful Dow Jones Hammer deployment
you should [inject corresponding access credentials](configuredeploy_overview.html#41-access-credentials-storage) to the credentials DynamoDB table defined in `credentials` section of `config.json`:
```
"credentials": {
    "ddb.table_name": "hammer-credentials"
},
```

#### 1.3.1. JIRA Integration

**Note**:
* you can use Dow Jones Hammer with any JIRA version that is supported by [jira library](https://pypi.org/project/jira/).
* Dow Jones Hammer supports only `OAuth` authentication on JIRA server. You need to [configure JIRA application accordingly](https://stackoverflow.com/questions/18153033/jira-python-oauth-how-to-get-the-parameters-for-authentication) and
[inject corresponding access credentials](configuredeploy_overview.html#41-access-credentials-storage) to the credentials DynamoDB table.

To configure JIRA integration parameters, you should edit the following configuration files:

1. The `config.json` file, **jira** section, following parameters:
    * **enabled**: enables/disables Dow Jones Hammer and JIRA integration. The default value is `false`;
    * **server**: defines the root URL of your JIRA server. The default value is `https://issues.example.com`;
    * **issue_type**: defines the type of JIRA issue that Dow Jones Hammer will raise in case it detects a vulnerability. The default value is `Task`.

    Configuration example:
    ```
    "jira": {
        "enabled": false,
        "server": "https://issues.example.com",
        "issue_type": "Task"
    }
    ```

2. The `ticket_owners.json` file, following parameters:
    * **jira_project**: JIRA project
    * **jira_owner**: JIRA assignee
    * **jira_parent_ticket**: JIRA parent ticket

    You can specify these parameters at **AWS account specific** or **global** settings. **AWS account specific** settings precede the **global** settings.

    Configuration example:
    ```
    {
        "account": {
            "1234567890123": {
                "jira_project": "AWSCORESEC",
                "jira_owner": "DevOps-CORE",
                "jira_parent_ticket": "AWSSEC-4321"
            }
        },
        "jira_project": "AWSSEC",
        "jira_owner": "DevOps-ENTERPRISE",
        "jira_parent_ticket": "AWSSEC-1234"
    }
    ```

    Also Dow Jones Hammer tries to detect person to report issue to by examining `owner` tag on affected resource (Security Group, S3 bucket, EBS volume/snapshot, RDS snapshot, etc).
    In case when such tag **exists** and is **valid JIRA user**, `jira_owner` parameter **is ignored** and discovered `owner` **is used instead** as a JIRA assignee.

#### 1.3.2. Slack Integration

There are two groups of messages which you can configure to forward to Slack:
* **hammer-internal** messages (logged to CloudWatch Logs) should be monitored to control Dow Jones Hammer functionality, [access problems](logging.html#6-logging-slave-account-access-problems), etc;
* **issue-specific** messages should be used for reporting purposes during issue lifecycle.

Also, in case Slack integration is enabled, Dow Jones Hammer Slack bot is launched. You can interact with it by sending direct messages or invite to any channel. Send `help` to get the list of supported commands. You can use it to check:
* Dow Jones Hammer status;
* configuration details.

To configure Slack integration parameters, you should edit the following configuration files:

1. The `config.json` file, **slack** section, following parameters:
    * **enabled**: globally enables/disables Dow Jones Hammer and Slack integration (for both **hammer-internal** and **issue-specific** messages, as well as for Dow Jones Hammer Slack bot). The default value is `false`;
    * **channels**: defines the patterns of **hammer-internal** messages that Dow Jones Hammer will post to Slack and the destination channels. The keys are Slack channels, the values are lists with PCRE regular expressions;
    * **ignore**: defines the patterns of **hammer-internal** messages that Dow Jones Hammer will not post to Slack channels. The keys are Slack channels, the values are lists with PCRE regular expressions;
    * **default_channel**: defines the default Slack channel where Dow Jones Hammer will post **hammer-internal** messages if there is no more specific message destination.

    Configuration example:
    ```
    "slack": {
        "enabled": true,
        "channels": {
            "hammer-errors": ["ERROR|WARNING|ALARM|Task timed out after|Access denied"]
        },
        "ignore": [],
        "default_channel": "hammer-dev"
    }
    ```

2. **slack_owner** parameter in the `ticket_owners.json` file to configure forwarding of **issue-specific** messages to Slack. The value of this parameter is a list with Slack channels (`#` prefixed) or users that will receive issue reports from Dow Jones Hammer.

    You can specify these parameter at **AWS account specific** or **global** settings. **AWS account specific** settings precede the **global** settings.

    Configuration example:
    ```
    {
        "account": {
            "1234567890123": {
                "slack_owner": "#devops-1234567890123"
            }
        },
        "slack_owner": ["#devops", "bob"]
    }
    ```
    Also Dow Jones Hammer tries to detect person to report issue to by examining `owner` tag on affected resource (Security Group, S3 bucket, EBS volume/snapshot, RDS snapshot, etc).
    In case when such tag **exists** and is **valid Slack user**, discovered `owner` **is used in addition to** `slack_owner` value.

### 1.4. Reporting Setup (CSV)

You can configure Dow Jones Hammer to send CSV with detected vulnerabilities to designated S3 bucket on a regular basis.
Use following configuration parameters in **csv** section:
* **enabled**: enables/disables CSV reporting;
* **schedule**: defines schedule for CSV reporting. Please use the standard **crontab** syntax to define the timing of this job;
* **slack_channel**: name of the slack channel (`#` prefixed) or user to send CSV reports to;
* **bucket**: name of the pre-created S3 bucket to put CSV reports to.

Configuration example:
```
"csv": {
    "enabled": true,
    "schedule": "0 9 * * 1",
    "bucket": "hammer-backup-bucket",
    "slack_channel": "#hammer-prod"
},
```

### 1.5. Azure Settings

**This step is required only if you intend to use Azure issue types** (check [multi-cloud overview](multicloud_overview.html)).

The **azure** section of the `config.json` file defines the Azure subscriptions to check:
* **accounts**: map of Azure subscription IDs to their names, used as account IDs/names by all Azure issue types. If the section is missing or **accounts** is empty, Azure support is disabled.

Azure service principal credentials (`tenant_id`, `client_id`, `client_secret`) are **not** stored in `config.json`. They are loaded from the `azure` item of the [credentials](#13-reporting-setup-jiraslack) DynamoDB table. Check [prerequisites](prerequisites.html#5-put-azuregcp-credentials-into-dynamodb) for details.

Configuration example:
```
"azure": {
    "accounts": {
        "00000000-0000-0000-0000-000000000000": "azure-prod",
        "11111111-1111-1111-1111-111111111111": "azure-dev"
    }
},
```

### 1.6. GCP Settings

**This step is required only if you intend to use GCP issue types** (check [multi-cloud overview](multicloud_overview.html)).

The **gcp** section of the `config.json` file defines the GCP projects to check:
* **accounts**: map of GCP project IDs to their names, used as account IDs/names by all GCP issue types. If the section is missing or **accounts** is empty, GCP support is disabled.

The GCP service account JSON key is **not** stored in `config.json`. It is loaded from the `gcp` item of the [credentials](#13-reporting-setup-jiraslack) DynamoDB table. Check [prerequisites](prerequisites.html#5-put-azuregcp-credentials-into-dynamodb) for details.

Configuration example:
```
"gcp": {
    "accounts": {
        "my-prod-project": "gcp-prod",
        "my-dev-project": "gcp-dev"
    }
},
```

## 2. Configure Issue-Specific Dow Jones Hammer Configuration Parameters

You can configure Dow Jones Hammer to detect, report, and remediate specific issues in the issue-specific branches of the `config.json` file. Check the issue-specific playbooks for further details.

### 2.1. S3 ACL Public Access

This section describes how to detect your AWS S3 buckets that are worldwide accessible by virtue of the ACL (Access Control List) settings. Refer to [issue-specific playbook](playbook1_s3_public_buckets_acl.html) for further details. 

Edit the **s3_bucket_acl** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-s3-public-bucket-acl`;
* **accounts**: *optional* comma-separated list of accounts to check and report for issue in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **ignore_accounts**: *optional* comma-separated list of accounts to ignore during check. Use this key to exclude accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **remediation_accounts**: *optional* comma-separated list of accounts to remediate issues in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that must pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.2. Insecure Services

This section describes how to detect your AWS security groups with worldwide accessible sensitive ports. Refer to [issue-specific playbook](playbook2_insecure_services.html) for further details. 

Edit the **secgrp_unrestricted_access** section of the `config.json` file to configure the handling of this issue. 

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write detected issues. The default value is `hammer-security-groups-unrestricted`;
* **accounts**: *optional* comma-separated list of accounts to check and report for issue in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **ignore_accounts**: *optional* comma-separated list of accounts to ignore during check. Use this key to exclude accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **remediation_accounts**: *optional* comma-separated list of accounts to remediate issues in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **restricted_ports**: a comma-separated list of ports in square brackets, which Dow Jones Hammer checks to be restricted;
* **reporting**: defines whether reporting is on or off. The default value is `false`;
* **remediation**: defines whether remediation is on or off. The default value is `false`.
* **remediation_retention_period**: the amount of days that must pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.3. IAM User Inactive Keys

This section describes how to detect that Dow Jones Hammer has not used your AWS IAM access keys for more than a number of days. Refer to [issue-specific playbook](playbook3_inactive_user_keys.html) for further details. 

Edit the **user_inactivekeys** section of the `config.json` file to configure the handling of this action.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-iam-user-keys-inactive`;
* **accounts**: *optional* comma-separated list of accounts to check and report for issue in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **ignore_accounts**: *optional* comma-separated list of accounts to ignore during check. Use this key to exclude accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **remediation_accounts**: *optional* comma-separated list of accounts to remediate issues in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **inactive_criteria_days**: the threshold amount of days when Dow Jones Hammer has not used the access keys to raise an alert. The default value is `1`;
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.4. IAM User Key Rotation

This section describes how to detect that no IAM key rotation has happened within the set timeframe. Refer to [issue-specific playbook](playbook4_keysrotation.html) for further details.

Edit the **user_keysrotation** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-iam-user-keys-rotation`;
* **accounts**: *optional* comma-separated list of accounts to check and report for issue in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **ignore_accounts**: *optional* comma-separated list of accounts to ignore during check. Use this key to exclude accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **remediation_accounts**: *optional* comma-separated list of accounts to remediate issues in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **rotation_criteria_days**: the threshold amount of days without key rotation that will trigger Dow Jones Hammer to raise an alert. The default value is `10` days.
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.5. S3 Policy Public Access

This section describes how to detect your AWS S3 buckets that are worldwide accessible by virtue of the S3 bucket policy. Refer to [issue-specific playbook](playbook5_s3_public_buckets_policy.html) for further details.

Edit the **s3_bucket_policy** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-s3-public-bucket-policy`;
* **accounts**: *optional* comma-separated list of accounts to check and report for issue in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **ignore_accounts**: *optional* comma-separated list of accounts to ignore during check. Use this key to exclude accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **remediation_accounts**: *optional* comma-separated list of accounts to remediate issues in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `7` days.

### 2.6. CloudTrail Logging Issues

This section describes how to detect whether AWS CloudTrail is not enabled for your account. Refer to [issue-specific playbook](playbook6_cloudtrail.html) for further details.

Edit the **cloudtrails** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-cloudtrails`;
* **accounts**: *optional* comma-separated list of accounts to check and report for issue in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **ignore_accounts**: *optional* comma-separated list of accounts to ignore during check. Use this key to exclude accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **reporting**: defines whether Dow Jones Hammer will report to JIRA and/or Slack in case it has detected an issue. The default value is `false`.

### 2.7. EBS Unencrypted Volumes

This section describes how to detect whether you have EBS volumes that are not encrypted at rest (as required by the PCI compliance rules). Refer to [issue-specific playbook](playbook7_ebs_unencrypted_volumes.html) for further details.

Edit the **ebs_unencrypted_volume** of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will put the detection results. The default value is `hammer-ebs-volumes-unencrypted`;
* **accounts**: *optional* comma-separated list of accounts to check and report for issue in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **ignore_accounts**: *optional* comma-separated list of accounts to ignore during check. Use this key to exclude accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`.

### 2.8. EBS Public Snapshots

This section describes how to detect whether snapshots of some of your EBS volumes are publicly available. Refer to [issue-specific playbook](playbook8_ebs_snapshots_public.html) for further details.

Edit the **ebs_public_snapshot** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will put detection results. The default value is `hammer-ebs-snapshots-public`;
* **accounts**: *optional* comma-separated list of accounts to check and report for issue in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **ignore_accounts**: *optional* comma-separated list of accounts to ignore during check. Use this key to exclude accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **remediation_accounts**: *optional* comma-separated list of accounts to remediate issues in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its auomatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.9. RDS Public Snapshots

This section describes how to detect your publicly accessible RDS snapshots. Refer to [issue-specific playbook](playbook9_rds_snapshots_public.html) for further details.

Edit the **rds_public_snapshot** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will put detection results. The default value is `hammer-rds-public-snapshots`.
* **accounts**: *optional* comma-separated list of accounts to check and report for issue in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **ignore_accounts**: *optional* comma-separated list of accounts to ignore during check. Use this key to exclude accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **remediation_accounts**: *optional* comma-separated list of accounts to remediate issues in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.10. SQS Public Policy

This section describes how to detect your publicly accessible SQS Queues. Refer to [issue-specific playbook](playbook10_sqs_public_policy.html) for further details.

Edit the **sqs_public_access** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will put detection results. The default value is `hammer-sqs-public-access`.
* **accounts**: *optional* comma-separated list of accounts to check and report for issue in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **ignore_accounts**: *optional* comma-separated list of accounts to ignore during check. Use this key to exclude accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **remediation_accounts**: *optional* comma-separated list of accounts to remediate issues in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.11. S3 Unencrypted Buckets

This section describes how to detect whether you have S3 buckets that are not encrypted at rest. Refer to [issue-specific playbook](playbook11_s3_unencryption.html) for further details.

Edit the **s3_encryption** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will put detection results. The default value is `hammer-s3-unencrypted`.
* **accounts**: *optional* comma-separated list of accounts to check and report for issue in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **ignore_accounts**: *optional* comma-separated list of accounts to ignore during check. Use this key to exclude accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **remediation_accounts**: *optional* comma-separated list of accounts to remediate issues in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.12. RDS Unencrypted Instances

This section describes how to detect whether you have RDS instances that are not encrypted at rest. Refer to [issue-specific playbook](playbook12_rds_unencryption.html) for further details.

Edit the **rds_encryption** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will put detection results. The default value is `hammer-rds-unencrypted`.
* **accounts**: *optional* comma-separated list of accounts to check and report for issue in square brackets. Use this key to override accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **ignore_accounts**: *optional* comma-separated list of accounts to ignore during check. Use this key to exclude accounts from **aws.accounts** in [config.json](#11-master-aws-account-settings);
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;

### 2.13. Public AMI issues

This section describes how to detect whether you have AMIs public access or not. Refer to [issue-specific playbook](playbook13_amis_public_access.html) for further details.

Edit the **public_ami_issues** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `true`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will put detection results. The default value is `hammer-public-amis`.
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.14. Azure Storage Public Access

This section describes how to detect Azure storage accounts that allow public blob access and contain publicly accessible (`Blob`/`Container` level) containers. Refer to [issue-specific playbook](playbook14_azure_storage_public_access.html) for further details.

Edit the **azure_storage_public_access** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `false`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-azure-storage-public-access`;
* **topic_name**: the name of the SNS topic used to trigger identification. The default value is `hammer-describe-azure-storage-public-access-lambda`;
* **accounts**: *optional* comma-separated list of subscriptions to check and report for issue in square brackets. Use this key to override subscriptions from [azure.accounts](#15-azure-settings);
* **ignore_accounts**: *optional* comma-separated list of subscriptions to ignore during check. Use this key to exclude subscriptions from [azure.accounts](#15-azure-settings);
* **remediation_accounts**: *optional* comma-separated list of subscriptions to remediate issues in square brackets. Use this key to override subscriptions from [azure.accounts](#15-azure-settings);
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.15. Azure NSG Unrestricted Access

This section describes how to detect Azure network security groups with inbound `Allow` rules that open sensitive ports to the Internet (`*`, `Internet`, `0.0.0.0/0`, `::/0`). Refer to [issue-specific playbook](playbook15_azure_nsg_unrestricted_access.html) for further details.

Edit the **azure_nsg_unrestricted_access** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `false`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-azure-nsg-unrestricted`;
* **topic_name**: the name of the SNS topic used to trigger identification. The default value is `hammer-describe-azure-nsg-lambda`;
* **accounts**: *optional* comma-separated list of subscriptions to check and report for issue in square brackets. Use this key to override subscriptions from [azure.accounts](#15-azure-settings);
* **ignore_accounts**: *optional* comma-separated list of subscriptions to ignore during check. Use this key to exclude subscriptions from [azure.accounts](#15-azure-settings);
* **remediation_accounts**: *optional* comma-separated list of subscriptions to remediate issues in square brackets. Use this key to override subscriptions from [azure.accounts](#15-azure-settings);
* **restricted_ports**: a comma-separated list of ports in square brackets, which Dow Jones Hammer checks to be restricted (same semantics as **restricted_ports** of [Insecure Services](#22-insecure-services));
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.16. Azure Unencrypted Disks

This section describes how to detect Azure managed disks encrypted only with platform-managed keys. Refer to [issue-specific playbook](playbook16_azure_unencrypted_disks.html) for further details.

Edit the **azure_disk_unencrypted** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `false`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-azure-disks-unencrypted`;
* **topic_name**: the name of the SNS topic used to trigger identification. The default value is `hammer-describe-azure-unencrypted-disks-lambda`;
* **accounts**: *optional* comma-separated list of subscriptions to check and report for issue in square brackets. Use this key to override subscriptions from [azure.accounts](#15-azure-settings);
* **ignore_accounts**: *optional* comma-separated list of subscriptions to ignore during check. Use this key to exclude subscriptions from [azure.accounts](#15-azure-settings);
* **require_customer_managed_key**: if `true`, only disks encrypted with a customer-managed key pass the check; if `false`, either a customer-managed key or Azure Disk Encryption passes the check. The default value is `false`;
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: remediation is not supported for this issue type, keep the default value `false`.

### 2.17. Azure Storage Keys Rotation

This section describes how to detect Azure storage account access keys that have not been rotated within the set timeframe while shared key access is allowed. Refer to [issue-specific playbook](playbook17_azure_storage_keys_rotation.html) for further details.

Edit the **azure_storage_keys_rotation** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `false`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-azure-storage-keys-rotation`;
* **topic_name**: the name of the SNS topic used to trigger identification. The default value is `hammer-describe-azure-storage-keys-rotation-lambda`;
* **accounts**: *optional* comma-separated list of subscriptions to check and report for issue in square brackets. Use this key to override subscriptions from [azure.accounts](#15-azure-settings);
* **ignore_accounts**: *optional* comma-separated list of subscriptions to ignore during check. Use this key to exclude subscriptions from [azure.accounts](#15-azure-settings);
* **remediation_accounts**: *optional* comma-separated list of subscriptions to remediate issues in square brackets. Use this key to override subscriptions from [azure.accounts](#15-azure-settings);
* **rotation_criteria_days**: the threshold amount of days without key rotation that will trigger Dow Jones Hammer to raise an alert. Keys with unknown creation time are always reported;
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.18. GCP Bucket Public Access

This section describes how to detect GCP Cloud Storage buckets whose IAM policy (or legacy ACL) grants access to `allUsers`/`allAuthenticatedUsers`. Refer to [issue-specific playbook](playbook18_gcp_bucket_public_access.html) for further details.

Edit the **gcp_bucket_public_access** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `false`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-gcp-bucket-public-access`;
* **topic_name**: the name of the SNS topic used to trigger identification. The default value is `hammer-describe-gcp-bucket-public-access-lambda`;
* **accounts**: *optional* comma-separated list of projects to check and report for issue in square brackets. Use this key to override projects from [gcp.accounts](#16-gcp-settings);
* **ignore_accounts**: *optional* comma-separated list of projects to ignore during check. Use this key to exclude projects from [gcp.accounts](#16-gcp-settings);
* **remediation_accounts**: *optional* comma-separated list of projects to remediate issues in square brackets. Use this key to override projects from [gcp.accounts](#16-gcp-settings);
* **enforce_public_access_prevention**: if `true`, remediation also sets `public_access_prevention` of the bucket to `enforced`. The default value is `false`;
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.19. GCP Firewall Unrestricted Access

This section describes how to detect enabled GCP VPC ingress firewall rules that open sensitive ports to `0.0.0.0/0` or `::/0`. Refer to [issue-specific playbook](playbook19_gcp_firewall_unrestricted_access.html) for further details.

Edit the **gcp_firewall_unrestricted_access** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `false`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-gcp-firewall-unrestricted`;
* **topic_name**: the name of the SNS topic used to trigger identification. The default value is `hammer-describe-gcp-firewall-lambda`;
* **accounts**: *optional* comma-separated list of projects to check and report for issue in square brackets. Use this key to override projects from [gcp.accounts](#16-gcp-settings);
* **ignore_accounts**: *optional* comma-separated list of projects to ignore during check. Use this key to exclude projects from [gcp.accounts](#16-gcp-settings);
* **remediation_accounts**: *optional* comma-separated list of projects to remediate issues in square brackets. Use this key to override projects from [gcp.accounts](#16-gcp-settings);
* **restricted_ports**: a comma-separated list of ports in square brackets, which Dow Jones Hammer checks to be restricted (same semantics as **restricted_ports** of [Insecure Services](#22-insecure-services));
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.20. GCP Unencrypted Disks

This section describes how to detect GCP Compute Engine disks encrypted only with Google-managed keys (no Cloud KMS or customer-supplied key). Refer to [issue-specific playbook](playbook20_gcp_unencrypted_disks.html) for further details.

Edit the **gcp_disk_unencrypted** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `false`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-gcp-disks-unencrypted`;
* **topic_name**: the name of the SNS topic used to trigger identification. The default value is `hammer-describe-gcp-unencrypted-disks-lambda`;
* **accounts**: *optional* comma-separated list of projects to check and report for issue in square brackets. Use this key to override projects from [gcp.accounts](#16-gcp-settings);
* **ignore_accounts**: *optional* comma-separated list of projects to ignore during check. Use this key to exclude projects from [gcp.accounts](#16-gcp-settings);
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: remediation is not supported for this issue type, keep the default value `false`.

### 2.21. GCP Service Account Keys Rotation

This section describes how to detect user-managed GCP service account keys that have not been rotated within the set timeframe. Refer to [issue-specific playbook](playbook21_gcp_sa_keys_rotation.html) for further details.

Edit the **gcp_sa_keys_rotation** section of the `config.json` file to configure the handling of this issue.

Parameters:
* **enabled**: enables/disables issue identification. The default value is `false`;
* **ddb.table_name**: the name of the DynamoDB table where Dow Jones Hammer will write issue detection results. The default value is `hammer-gcp-sa-keys-rotation`;
* **topic_name**: the name of the SNS topic used to trigger identification. The default value is `hammer-describe-gcp-sa-keys-rotation-lambda`;
* **accounts**: *optional* comma-separated list of projects to check and report for issue in square brackets. Use this key to override projects from [gcp.accounts](#16-gcp-settings);
* **ignore_accounts**: *optional* comma-separated list of projects to ignore during check. Use this key to exclude projects from [gcp.accounts](#16-gcp-settings);
* **remediation_accounts**: *optional* comma-separated list of projects to remediate issues in square brackets. Use this key to override projects from [gcp.accounts](#16-gcp-settings);
* **rotation_criteria_days**: the threshold amount of days after key creation that will trigger Dow Jones Hammer to raise an alert;
* **reporting**: defines whether Dow Jones Hammer will report detected issues to JIRA/Slack. The default value is `false`;
* **remediation**: defines whether Dow Jones Hammer will automatically remediate the detected issue. The default value is `false`;
* **remediation_retention_period**: the amount of days that should pass between the detection of an issue and its automatic remediation by Dow Jones Hammer. The default value is `0`.

### 2.22. Azure/GCP Configuration Example

```
"azure_nsg_unrestricted_access": {
    "enabled": true,
    "ddb.table_name": "hammer-azure-nsg-unrestricted",
    "topic_name": "hammer-describe-azure-nsg-lambda",
    "restricted_ports": [21, 22, 23, 3389, 1433, 3306, 5432, 27017],
    "ignore_accounts": ["11111111-1111-1111-1111-111111111111"],
    "reporting": true,
    "remediation": false,
    "remediation_retention_period": 21
},
"gcp_sa_keys_rotation": {
    "enabled": true,
    "ddb.table_name": "hammer-gcp-sa-keys-rotation",
    "topic_name": "hammer-describe-gcp-sa-keys-rotation-lambda",
    "rotation_criteria_days": 90,
    "reporting": true,
    "remediation": false,
    "remediation_retention_period": 0
}
```
