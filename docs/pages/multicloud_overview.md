---
title: Multi-Cloud (Azure and GCP) Overview
keywords: multicloud, azure, gcp
sidebar: mydoc_sidebar
permalink: multicloud_overview.html
---

## 1. Introduction

In addition to AWS, Dow Jones Hammer can identify, report and remediate security issues in **Microsoft Azure** subscriptions and **Google Cloud Platform (GCP)** projects.
Azure and GCP support is optional: if you do not configure the `azure`/`gcp` sections of `config.json`, Dow Jones Hammer behaves exactly as an AWS-only deployment.

## 2. Architecture

The Dow Jones Hammer control plane stays in your master AWS account. No Hammer infrastructure is deployed to Azure or GCP:

* **Identification** of Azure/GCP issues runs as additional AWS Lambda functions deployed by the [identification stack](deployment_cloudformation.html#313-identification-functionality). Every issue type uses the same pattern as the AWS issue types: a CloudWatch scheduled *initiate* Lambda publishes one SNS message per subscription/project, and the *describe* Lambda subscribed to that SNS topic calls the Azure/GCP APIs and writes the results to DynamoDB. These Lambda functions use the `python3.9` runtime (the AWS ones keep `python3.6`).
* **Issues** are stored in DynamoDB, one table per issue type, with the same key schema as AWS issue tables (HASH key `account_id`, RANGE key `issue_id`).
* **Reporting and remediation** run on the existing reporting/remediation EC2 instance, scheduled by `cronjobs/automation_scheduler.py`, and reuse the existing JIRA/Slack reporting, whitelisting, ticket owners and remediation retention logic.
* **CSV reports** and the **REST API** cover Azure/GCP issue types as well.

Since Azure and GCP APIs are global per subscription/project, the SNS payload of Azure/GCP identification is `{"account_id", "account_name", "sns_arn"[, "request_id"]}`, without region chaining. The location of a resource is stored in the `issue_details.location` field of the issue.

**Note**: identification Lambda functions (and the reporting/remediation EC2) need outbound HTTPS access to Azure (`login.microsoftonline.com`, `management.azure.com`) and GCP (`oauth2.googleapis.com`, `*.googleapis.com`) endpoints. If you run identification Lambda functions in a VPC (**LambdaSubnets**/**LambdaSecurityGroups** parameters), make sure the subnets have a route to the Internet through a NAT gateway.

## 3. Provider Abstraction

Dow Jones Hammer code uses a small provider layer:

* `library/cloud.py`: `CloudProvider` enum (`aws`, `azure`, `gcp`) and `CloudAccount` base class;
* `library/azure/`: `AzureAccount` (Azure subscription) and Azure issue checkers. Azure SDKs: `azure-identity`, `azure-mgmt-storage`, `azure-mgmt-network`, `azure-mgmt-compute`;
* `library/gcp/`: `GCPAccount` (GCP project) and GCP issue checkers. GCP SDKs: `google-auth`, `google-cloud-storage`, `google-cloud-compute`, `google-cloud-iam`.

Cloud SDKs are installed per Lambda package from the `requirements.txt` file of each Lambda directory (by `deployment/build_packages.sh`) and on the reporting/remediation EC2 from `hammer/reporting-remediation/requirements.txt`. Azure/GCP SDKs require Python 3.8 or newer, so reporting/remediation EC2 must use Python 3.9 (see [cronjobs.python](editconfig.html#12-scheduling-settings)) when Azure/GCP modules are enabled.

## 4. Accounts

The notion of an *account* is generalised:

| Cloud | Account   | Example                                |
|-------|-----------|----------------------------------------|
| AWS   | Account ID      | `123456789012`                   |
| Azure | Subscription ID | `00000000-0000-0000-0000-000000000000` |
| GCP   | Project ID      | `my-gcp-project`                 |

Azure subscriptions are configured in the [azure](editconfig.html#15-azure-settings) section and GCP projects in the [gcp](editconfig.html#16-gcp-settings) section of `config.json`. The issue-specific `accounts`, `ignore_accounts` and `remediation_accounts` options, as well as `ticket_owners.json`, `whitelist.json` and `fixnow.json`, are keyed by subscription ID / project ID for Azure/GCP issue types.

Every Azure/GCP issue stores `issue_details.provider` (`azure`/`gcp`), `issue_details.name`, `issue_details.location` and `issue_details.tags`. Azure tags and GCP labels are used to resolve the owner, business unit and product of a resource exactly like AWS tags.

## 5. Credentials

Azure and GCP credentials are **never** stored in `config.json`. Like JIRA and Slack credentials, they are stored in the encrypted `hammer-credentials` DynamoDB table:

| `service` item key | `credentials` value                                                         |
|--------------------|-----------------------------------------------------------------------------|
| `azure`            | `{"tenant_id": "...", "client_id": "...", "client_secret": "..."}` of one service principal with access to all configured subscriptions |
| `gcp`              | the JSON key (as a dictionary) of one service account with access to all configured projects |

Check [prerequisites](prerequisites.html#3-microsoft-azure-prerequisites) for the required Azure roles and GCP roles and for AWS CLI commands to put the credentials into DynamoDB.
No new cross-account AWS IAM roles are required for Azure/GCP; the identification Lambda functions and the reporting/remediation EC2 read the credentials with their existing IAM roles.

## 6. Issue Types

|Name                                                                                       |Cloud|Config section                    |DynamoDB table                       |Remediation|
|-------------------------------------------------------------------------------------------|-----|----------------------------------|-------------------------------------|:---------:|
|[Azure Storage Public Access](playbook14_azure_storage_public_access.html)                 |Azure|`azure_storage_public_access`     |`hammer-azure-storage-public-access` |**+**      |
|[Azure NSG Unrestricted Access](playbook15_azure_nsg_unrestricted_access.html)             |Azure|`azure_nsg_unrestricted_access`   |`hammer-azure-nsg-unrestricted`      |**+**      |
|[Azure Unencrypted Disks](playbook16_azure_unencrypted_disks.html)                         |Azure|`azure_disk_unencrypted`          |`hammer-azure-disks-unencrypted`     |           |
|[Azure Storage Keys Rotation](playbook17_azure_storage_keys_rotation.html)                 |Azure|`azure_storage_keys_rotation`     |`hammer-azure-storage-keys-rotation` |**+**      |
|[GCP Bucket Public Access](playbook18_gcp_bucket_public_access.html)                       |GCP  |`gcp_bucket_public_access`        |`hammer-gcp-bucket-public-access`    |**+**      |
|[GCP Firewall Unrestricted Access](playbook19_gcp_firewall_unrestricted_access.html)       |GCP  |`gcp_firewall_unrestricted_access`|`hammer-gcp-firewall-unrestricted`   |**+**      |
|[GCP Unencrypted Disks](playbook20_gcp_unencrypted_disks.html)                             |GCP  |`gcp_disk_unencrypted`            |`hammer-gcp-disks-unencrypted`       |           |
|[GCP Service Account Keys Rotation](playbook21_gcp_sa_keys_rotation.html)                  |GCP  |`gcp_sa_keys_rotation`            |`hammer-gcp-sa-keys-rotation`        |**+**      |

Check [Security Features](features.html) for issue descriptions and [config.json](editconfig.html#2-configure-issue-specific-hammer-configuration-parameters) for issue-specific configuration options.

## 7. Enabling Azure/GCP Support

1. Create the Azure service principal and/or GCP service account and grant them the required roles ([prerequisites](prerequisites.html#3-microsoft-azure-prerequisites)).
2. Deploy (or update) Dow Jones Hammer with [CloudFormation](deployment_cloudformation.html) or [Terraform](deployment_terraform.html). The new DynamoDB tables and identification Lambda functions are created by the existing stacks.
3. Put the Azure/GCP credentials into the `hammer-credentials` DynamoDB table ([prerequisites](prerequisites.html#5-put-azuregcp-credentials-into-dynamodb)).
4. Add your subscriptions/projects to the `azure`/`gcp` sections of `config.json`, set `cronjobs.python` to `python3.9`, and enable the desired issue-specific sections ([config.json](editconfig.html)).
