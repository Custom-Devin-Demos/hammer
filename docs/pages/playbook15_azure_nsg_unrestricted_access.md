---
title: Azure NSG Unrestricted Access
keywords: playbook15
sidebar: mydoc_sidebar
permalink: playbook15_azure_nsg_unrestricted_access.html
---

# Playbook 15: Azure NSG Unrestricted Access (Public Access to Sensitive Ports Allowed)

## Introduction

This playbook describes how to configure Dow Jones Hammer to detect Azure network security groups (NSG) which allow inbound access to sensitive ports from any address in the Internet.
It is the Azure equivalent of [Playbook 2: Insecure Services](playbook2_insecure_services.html).

## 1. Issue Identification

Dow Jones Hammer checks custom security rules of every network security group in the configured Azure subscriptions and detects rules which:
* have `Inbound` direction and `Allow` access;
* have source address prefix (`sourceAddressPrefix` or any of `sourceAddressPrefixes`) `*`, `Any`, `Internet`, `0.0.0.0/0` or `::/0`;
* have destination port range(s) (`*`, single port or port range) intersecting with the `restricted_ports` list from the configuration.

`Icmp` rules are skipped (they do not have ports). Default NSG rules are not checked as they never allow inbound access from the Internet.

When Dow Jones Hammer detects an issue, it writes the issue to the designated DynamoDB table. The issue id is the NSG resource id in lower case.

According to the [Dow Jones Hammer architecture](/index.html), the issue identification functionality uses two Lambda functions (running in the Hammer AWS account and accessing Azure with the service principal credentials stored in the `hammer-credentials` DynamoDB table under the `azure` key).
The table lists the Python modules that implement this functionality:

|Designation   |Path                  |
|--------------|:--------------------:|
|Initialization|`hammer/identification/lambdas/azure-nsg-issues-identification/initiate_to_desc_azure_nsg_issues.py`|
|Identification|`hammer/identification/lambdas/azure-nsg-issues-identification/describe_azure_nsg_issues.py`|

## 2. Issue Reporting

You can configure automatic reporting of cases when Dow Jones Hammer identifies an issue of this type. Dow Jones Hammer supports integration with [JIRA](https://www.atlassian.com/software/jira) and [Slack](https://slack.com/).
These types of reporting are independent from one another and you can turn them on/off in the Dow Jones Hammer configuration.

Thus, in case you have turned on the reporting functionality for this issue and configured corresponding integrations, Dow Jones Hammer, as [defined in the configuration](#43-the-ticket_ownersjson-file), can:
* raise a JIRA ticket and assign it to a specific person in your organization;
* send the issue notification to the Slack channel or directly to a Slack user.

The JIRA ticket contains the subscription, NSG name, location, resource group, the table with unrestricted rules (name, priority, protocol, ports, source), attached network interfaces/subnets and NSG tags.

Additionally Dow Jones Hammer tries to detect person to report issue to by examining `owner` tag on affected NSG (`bu` and `product` tags are used the same way). In case when such tag **exists** and is **valid JIRA/Slack user**:
* for JIRA: `jira_owner` parameter from [ticket_owners.json](#43-the-ticket_ownersjson-file) **is ignored** and discovered `owner` **is used instead** as a JIRA assignee;
* for Slack: discovered `owner` **is used in addition to** `slack_owner` value from [ticket_owners.json](#43-the-ticket_ownersjson-file).

This Python module implements the issue reporting functionality:
```
hammer/reporting-remediation/reporting/create_azure_nsg_issue_tickets.py
```

## 3. Issue Remediation

### 3.1 Automatic

To reduce the workload of your DevOps engineers and mitigate the threats stemming from this issue, you can configure automatic remediation of issues. It means that in case Dow Jones Hammer has detected and reported an issue, but the assignee of the report has not remediated the issue within a timeframe specified in the configuration, the Dow Jones Hammer remediation job will adjust the NSG to eliminate this vulnerability.

In this specific case, Dow Jones Hammer:
* saves the NSG definition (as Azure returns it) to the S3 backup bucket (`aws.s3_backup_bucket`) under `azure_nsg/<subscription id>/<resource group>/<nsg name>_<timestamp>.json`;
* removes world-wide open source prefixes from every offending rule; if no other sources are left in the rule, the source is replaced with the `VirtualNetwork` service tag (access from the Internet is removed while access from the virtual network is preserved).

This Python module implements the issue remediation functionality:
```
hammer/reporting-remediation/remediation/clean_azure_nsg_issues.py
```

### 3.2 Manual

To retain full control on the remediation functionality you can disable automatic remediation in [config.json](#41-the-configjson-file) and launch it manually:
1. Login to Dow Jones Hammer reporting and remediation EC2 via SSH with **centos** user and ssh key you created during [deployment](configuredeploy_overview.html#25-create-ec2-key-pair-for-hammer): `ssh -l centos -i <private_key> <EC2_IP>`
2. Become **root** user: `sudo su -`
3. Change directory to Dow Jones Hammer sources: `cd /hammer-correlation-engine`
4. Launch Dow Jones Hammer remediation script: `python3.9 -m remediation.clean_azure_nsg_issues`
5. Confirm or refuse remediation of each issue separately

### 3.3 Rollback

Rules backup is a JSON file with the NSG definition. To roll back a remediated rule, restore its `sourceAddressPrefix`/`sourceAddressPrefixes` from the backup with the Azure portal or Azure CLI (`az network nsg rule update`).

## 4. Setup Instructions For This Issue

To configure the detection, reporting, and remediation of this issue, you should edit the following sections of the Dow Jones Hammer configuration files:

### 4.1. The config.json File

The **config.json** file is the main configuration file for Dow Jones Hammer that is available at `deployment/terraform/accounts/sample/config/config.json`.
Azure subscriptions to check are listed in the `azure.accounts` section (`{"subscription id": "subscription name"}`).
To identify, report, and remediate issues of this type, you should add the following parameters in the **azure_nsg_unrestricted_access** section of the **config.json** file:

|Parameter Name                |Description                            | Default Value|
|------------------------------|---------------------------------------|:------------:|
|`enabled`                     |Toggles issue detection for this issue |`false`|
|`ddb.table_name`              |The name of the DynamoDB table to which Dow Jones Hammer would record detected issues of this type|`hammer-azure-nsg-unrestricted`|
|`topic_name`                  |The name of the SNS topic used to trigger identification lambda|`hammer-describe-azure-nsg-lambda`|
|`accounts`                    |*Optional* comma-separated list of subscriptions to limit check for|`azure.accounts` from `config.json`|
|`ignore_accounts`             |*Optional* comma-separated list of subscriptions to exclude from check|`[]`|
|`restricted_ports`            |List of ports which must not be open to the Internet|`[21, 22, 23, 3389, 1433, 1521, 3306, 5432, 27017, 28017, ...]`|
|`reporting`                   |Toggle Dow Jones Hammer reporting functionality for this issue|`false`|
|`remediation`                 |Toggle Dow Jones Hammer automatic remediation functionality for this issue|`false`|
|`remediation_accounts`        |*Optional* comma-separated list of subscriptions to remediate|`azure.accounts` from `config.json`|
|`remediation_retention_period`|The amount of days to pass between issue detection and its automatic remediation by Dow Jones Hammer. The value `0` denotes that Dow Jones Hammer will remediate the issue at once.|`365`|

Sample **config.json** section:
```
"azure_nsg_unrestricted_access": {
    "enabled": true,
    "ddb.table_name": "hammer-azure-nsg-unrestricted",
    "topic_name": "hammer-describe-azure-nsg-lambda",
    "restricted_ports": [21, 22, 23, 3389, 1433, 1521, 3306, 5432, 27017, 28017],
    "accounts": ["00000000-0000-0000-0000-000000000001"],
    "reporting": true,
    "remediation": false,
    "remediation_retention_period": 21
}
```

### 4.2. The whitelist.json File

You can define exceptions to issue detection settings for specific NSGs. To configure such exceptions, you should edit the **azure_nsg_unrestricted_access** section of the **whitelist.json** configuration file as follows:

|Parameter Key | Parameter Value(s)|
|:------------:|:-----------------:|
|Azure Subscription ID|NSG resource ids (lower case)|

Sample **whitelist.json** section:
```
"azure_nsg_unrestricted_access": {
    "00000000-0000-0000-0000-000000000001": ["/subscriptions/00000000-0000-0000-0000-000000000001/resourcegroups/rg-web/providers/microsoft.network/networksecuritygroups/nsg-bastion"]
}
```

The **fixnow.json** file uses the same format to force remediation of an issue before `remediation_retention_period` passes.

### 4.3. The ticket_owners.json File

You should use the **ticket_owners.json** file to configure the integration of Dow Jones Hammer with JIRA and/or Slack for issue reporting purposes.

You can configure these parameters for specific Azure subscriptions (use subscription id as the account key) and globally. Account-specific settings precede the global settings in the **ticket_owners.json** configuration file.

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

The Hammer service principal needs the following permissions in every checked subscription:

|Functionality |Permissions|
|--------------|-----------|
|Identification/Reporting|`Microsoft.Network/networkSecurityGroups/read` (included in the built-in `Reader` role)|
|Remediation   |`Microsoft.Network/networkSecurityGroups/read`, `Microsoft.Network/networkSecurityGroups/securityRules/write` (included in the built-in `Network Contributor` role)|

The identification lambda requires the `azure-identity` and `azure-mgmt-network` Python packages (installed from the lambda `requirements.txt`).

## 5. Logging

Dow Jones Hammer uses **CloudWatch Logs** for logging purposes.

Dow Jones Hammer automatically sets up CloudWatch Log Groups and Log Streams for this issue when you deploy Dow Jones Hammer.

### 5.1. Issue Identification Logging

Dow Jones Hammer issue identification functionality uses two Lambda functions:

* Initialization: this Lambda function selects Azure subscriptions to check for this issue as designated in the Dow Jones Hammer configuration files and triggers the check.
* Identification: this Lambda function identifies this issue for each subscription selected at the previous step.

You can see the logs for each of these Lambda functions in the `/aws/lambda/<lambda function name>` Log Groups of the initialization/identification Lambda functions created for this issue by the identification CloudFormation/Terraform stack.

### 5.2. Issue Reporting/Remediation Logging

Dow Jones Hammer issue reporting/remediation functionality uses ```/aws/ec2/hammer-reporting-remediation``` CloudWatch Log Group for logging. The Log Group contains issue-specific Log Streams named as follows:

|Designation|CloudWatch Log Stream Name                   |
|-----------|---------------------------------------------|
|Reporting  |`reporting.create_azure_nsg_issue_tickets`|
|Remediation|`remediation.clean_azure_nsg_issues`|

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

|Key                 |Type  |Description                                     |Example                          |
|--------------------|:----:|------------------------------------------------|---------------------------------|
|`provider`          |string|Cloud provider                                  |`azure`                          |
|`name`              |string|NSG name                                        |`nsg-web`                        |
|`location`          |string|Azure location of NSG                           |`westeurope`                     |
|`resource_group`    |string|NSG resource group                              |`rg-web`                         |
|`rules`             |list  |Unrestricted inbound rules                      |`[{"name": "allow-ssh", "priority": 100, "protocol": "Tcp", "ports": "22", "source": "*"}]`|
|`network_interfaces`|list  |Resource ids of attached network interfaces     |`["/subscriptions/.../networkInterfaces/nic-web"]`|
|`subnets`           |list  |Resource ids of attached subnets                |`["/subscriptions/.../virtualNetworks/vnet/subnets/web"]`|
|`tags`              |map   |Tags associated with NSG                        |`{"owner": "alice", "bu": "news"}`|
