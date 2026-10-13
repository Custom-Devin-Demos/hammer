---
title: GCP Firewall Unrestricted Access
keywords: playbook19
sidebar: mydoc_sidebar
permalink: playbook19_gcp_firewall_unrestricted_access.html
---

# Playbook 19: GCP Firewall Unrestricted Access (Public Access to Sensitive Ports Allowed)

## Introduction

This playbook describes how to configure Dow Jones Hammer to detect GCP VPC firewall rules which allow access to sensitive ports from the whole Internet. It is the GCP equivalent of [Playbook 2: Insecure Services](playbook2_insecure_services.html).

## 1. Issue Identification

Dow Jones Hammer lists VPC firewall rules of each configured GCP project and identifies rules that:
* have ```INGRESS``` direction and are not disabled;
* have ```0.0.0.0/0``` or ```::/0``` in ```sourceRanges```;
* have at least one ```allowed``` entry with:
  * protocol ```all```, or
  * protocol ```tcp```/```udp```/```sctp``` (or protocol numbers ```6```/```17```/```132```) without ports (all ports) or with ports/port ranges intersecting with ```restricted_ports``` from the configuration.

ICMP and other protocols without ports (```esp```, ```ah```, ```ipip```, etc.) are not considered as an issue. ```denied``` rules and ```EGRESS``` rules are skipped.

When Dow Jones Hammer detects an issue, it writes the issue to the designated DynamoDB table. Issue id is the firewall rule name (unique within GCP project). Issues for firewall rules which were removed or restricted are marked as resolved.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions.
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/gcp-firewall-issues-identification/initiate_to_desc_gcp_firewall_issues.py`|
|Identification|`hammer/identification/lambdas/gcp-firewall-issues-identification/describe_gcp_firewall_issues.py`|

The checker logic is implemented in `hammer/library/gcp/firewall.py`.

## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

JIRA ticket contains GCP project, firewall rule name, network, priority, target tags/service accounts and the table with world-wide open protocols, ports and source ranges.

GCP firewall rules do not support labels, so the owner, business unit and product are resolved from [ticket_owners.json](#43-the-ticket_ownersjson-file) by GCP project id (business unit can also be guessed from rule name using `bu_list` from **config.json**).

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_gcp_firewall_issue_tickets.py
```

## 3. Issue Remediation

### 3.1 Automatic

To reduce the workload of your DevOps engineers and mitigate the threats stemming from this issue, you can set up automatic remediation of issues. It means that in case Dow Jones Hammer has detected and reported an issue, but the assignee of the report has not remediated the issue within a timeframe specified in the configuration, the Dow Jones Hammer remediation job will adjust the settings of firewall rules.

In this specific case, issue remediation means that Dow Jones Hammer will:
* save the pre-remediation firewall rule configuration (as GCP returns it) to the S3 backup bucket (`aws.s3_backup_bucket` from **config.json**) by `gcp_firewall/<project id>/<rule name>_<timestamp>.json` key;
* patch the firewall rule removing ```0.0.0.0/0```/```::/0``` from ```sourceRanges```;
* **disable** the firewall rule if no other source ranges remain (an ingress rule without source ranges, tags or service accounts would be open to the world again).

Please note that a GCP firewall rule applies source ranges to all its ```allowed``` entries, so removing the world-wide open range also restricts other (not sensitive) ports of the same rule. Split such rules if public access to not sensitive ports is required.

To rollback the remediation, restore `sourceRanges` and `disabled` values from the backup (`FirewallOperations.restore_s3` in `hammer/library/gcp/firewall.py` does that for the most recent backup), for example with `gcloud compute firewall-rules update <rule name> --source-ranges=<ranges from backup> --no-disabled --project=<project id>`.

This Python module implements the issue remediation functionality:
```
hammer/reporting-remediation/remediation/clean_gcp_firewall_issues.py
```

### 3.2 Manual

To retain full control on the remediation functionality you can disable automatic remediation in [config.json](#41-the-configjson-file) and launch it manually:
1. Login to Dow Jones Hammer reporting and remediation EC2 via SSH with **centos** user and ssh key you created during [deployment](configuredeploy_overview.html#25-create-ec2-key-pair-for-hammer): `ssh -l centos -i <private_key> <EC2_IP_Address>`
2. Become **root** user: `sudo su -`
3. Change directory to Dow Jones Hammer sources: `cd /hammer-correlation-engine`
4. Launch Dow Jones Hammer remediation script: `python3.9 -m remediation.clean_gcp_firewall_issues` (use the interpreter configured in `cronjobs.python`)
5. Confirm or refuse remediation of each issue separately

## 4. Setup Instructions For This Issue

To configure the detection, reporting, and remediation of this issue, you should edit the following sections of the Dow Jones Hammer configuration files.

GCP projects are configured in the **gcp** section of **config.json** and the service account key is stored in the `hammer-credentials` DynamoDB table under the `gcp` key (see [prerequisites](prerequisites.html)).

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
To identify, report, and remediate issues of this type, you should add the following parameters in the **gcp_firewall_unrestricted_access** section of the **config.json** file:

|Parameter Name                |Description                                                                                       |Default Value|
|------------------------------|--------------------------------------------------------------------------------------------------|:-----------:|
|`enabled`                     |Toggles issue detection for this issue                                                            |`false`|
|`ddb.table_name`              |The name of the DynamoDB table to which Dow Jones Hammer would record detected issues of this type|`hammer-gcp-firewall-unrestricted`|
|`topic_name`                  |The name of the SNS topic used to trigger identification lambda                                   |`hammer-describe-gcp-firewall-lambda`|
|`accounts`                    |*Optional* list of GCP project ids to limit check for                                             |`gcp.accounts` from `config.json`|
|`ignore_accounts`             |*Optional* list of GCP project ids to exclude from check                                          |`[]`|
|`restricted_ports`            |List of ports which must not be accessible from the whole Internet                                |`[21, 22, 23, 3389, 1433, 1521, 3306, 5432, 27017, 28017, 2375]`|
|`reporting`                   |Toggle Dow Jones Hammer reporting functionality for this issue                                    |`false`|
|`remediation`                 |Toggle Dow Jones Hammer automatic remediation functionality for this issue                        |`false`|
|`remediation_accounts`        |*Optional* list of GCP project ids to limit remediation for                                       |`accounts` value|
|`remediation_retention_period`|The amount of days to pass between issue detection and its automatic remediation                 |`21`|

Sample **config.json** section:
```
"gcp_firewall_unrestricted_access": {
    "enabled": true,
    "ddb.table_name": "hammer-gcp-firewall-unrestricted",
    "topic_name": "hammer-describe-gcp-firewall-lambda",
    "restricted_ports": [21, 22, 23, 3389, 1433, 1521, 3306, 5432, 27017, 28017, 2375],
    "reporting": true,
    "remediation": false,
    "remediation_retention_period": 21
}
```

### 4.2. The whitelist.json File

You can define exceptions to issue detection settings for specific firewall rules. To configure such exceptions, you should edit the **gcp_firewall_unrestricted_access** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s) |
|:----:|:-----:|
|GCP Project ID|Firewall rule names|

Sample **whitelist.json** section:
```
"gcp_firewall_unrestricted_access": {
    "example-prod-project": ["allow-public-sftp", "default-allow-ssh"]
}
```

### 4.3. The ticket_owners.json File

You should use the **ticket_owners.json** file to configure the integration of Dow Jones Hammer with JIRA and/or Slack for issue reporting purposes.

You can configure these parameters for specific GCP projects and globally. Project-specific settings (keyed by GCP project id in the `account` section) precede the global settings in the **ticket_owners.json** configuration file.

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
        "example-prod-project": {
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

### 4.4. Required GCP Permissions

The service account configured for Dow Jones Hammer needs the following permissions in each checked GCP project:

|Functionality |Permissions|Predefined Role|
|--------------|-----------|---------------|
|Identification|`compute.firewalls.list`, `compute.firewalls.get`|**Compute Network Viewer** (`roles/compute.networkViewer`) or **Viewer** (`roles/viewer`)|
|Remediation   |`compute.firewalls.update`, `compute.networks.updatePolicy`, `compute.globalOperations.get`|**Compute Security Admin** (`roles/compute.securityAdmin`)|

The reporting/remediation EC2 instance role also needs `s3:PutObject`/`s3:GetObject`/`s3:ListBucket` on the backup bucket (already granted by the standard Dow Jones Hammer deployment).

## 5. Logging

Dow Jones Hammer uses **CloudWatch Logs** for logging purposes.

Dow Jones Hammer automatically sets up CloudWatch Log Groups and Log Streams for this issue when you deploy Dow Jones Hammer.

### 5.1. Issue Identification Logging

Dow Jones Hammer issue identification functionality uses two Lambda functions:

* Initialization: this Lambda function selects GCP projects to check for this issue as designated in the Dow Jones Hammer configuration files and triggers the check.
* Identification: this Lambda function identifies this issue for each GCP project selected at the previous step.

You can see the logs for each of these Lambda functions in the following Log Groups:

|Lambda Function|CloudWatch Log Group Name                    |
|---------------|---------------------------------------------|
|Initialization |`/aws/lambda/hammer-initiate-gcp-firewall`   |
|Identification |`/aws/lambda/hammer-describe-gcp-firewall`   |

### 5.2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name                           |
|-----------|-----------------------------------------------------|
|Reporting  |`reporting.create_gcp_firewall_issue_tickets`        |
|Remediation|`remediation.clean_gcp_firewall_issues`              |

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

|Key                      |Type  |Description                                                    |Example                          |
|-------------------------|:----:|---------------------------------------------------------------|---------------------------------|
|`provider`               |string|Cloud provider                                                 |`gcp`                            |
|`name`                   |string|Firewall rule name                                             |`default-allow-ssh`              |
|`location`               |string|Firewall rule location (VPC firewall rules are global)         |`global`                         |
|`network`                |string|VPC network name                                               |`default`                        |
|`priority`               |number|Firewall rule priority                                         |`65534`                          |
|`rules`                  |list  |World-wide open access (protocol, ports, source, priority)     |`[{"protocol": "tcp", "ports": "22", "source": "0.0.0.0/0", "priority": 65534}]`|
|`target_tags`            |list  |Network tags of target instances (empty - all instances)       |`["web"]`                        |
|`target_service_accounts`|list  |Service accounts of target instances                           |`[]`                             |
|`tags`                   |map   |Always empty (GCP firewall rules do not support labels)        |`{}`                             |
