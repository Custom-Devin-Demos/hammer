---
title: Prerequisites
keywords: Prerequisites
sidebar: mydoc_sidebar
permalink: prerequisites.html
---

This section describes steps that you should take before proceeding to Dow Jones Hammer configuration and deployment.


## 1. Amazon Web Services Command Line Interface Setup

To make Dow Jones Hammer configuration more convenient, you should install AWS Command Line Interface (CLI) - a unified tool to manage your AWS services. With just one tool to download and configure, you can control multiple AWS services from the command line and automate them through scripts.

You will be using AWS CLI tools to perform the following tasks related to Dow Jones Hammer setup:
* S3 Bucket creation
* Lambda packages upload

Check AWS CLI documentation for further details: [https://aws.amazon.com/cli/](https://aws.amazon.com/cli/).

## 2. Access Rights for Amazon Products

This section describes the following two sets of AWS access rights:
* access rights required to deploy Dow Jones Hammer
* access rights required to run Dow Jones Hammer

### 2.1. Dow Jones Hammer Deployment

To deploy Dow Jones Hammer, you have to have administrator access rights for your master AWS account and slave AWS accounts.

**Note**: During the Dow Jones Hammer Deployment a DynamoDB table for Slack and/or JIRA credentials will be created. To keep this data secure, the table will be [encrypted at rest](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html).

### 2.2. Dow Jones Hammer Operation

**Identification** / **Reporting**

Dow Jones Hammer needs following access rights to perform issues identification and reporting:
1. Master Account:
    * Read-write access to CloudWatch and DynamoDB.
    * Read-only access to AWS services for which you have enabled issue identification.
2. Slave Accounts:
    * Read-only access to the AWS services for which you have enabled issue identification.

**Remediation**

In case you have configured Dow Jones Hammer to perform issue reporting, Dow Jones Hammer needs following access rights:
1. Master Account:
    * Read-write access to CloudWatch, DynamoDB and AWS services for which you have enabled remediation.
    * Read-only access to other AWS services for which you have *not* enabled issue remediation.
2. Slave Accounts:
    * Read-write access to AWS services for which you have enabled remediation.
    * Read-only access to other AWS services for which you have *not* enabled issue remediation.

## 3. Microsoft Azure Prerequisites

**This step is required only if you intend to use Azure issue types** (check [multi-cloud overview](multicloud_overview.html)).

Dow Jones Hammer accesses Azure subscriptions with a single **service principal** (Microsoft Entra ID application with a client secret) that has role assignments in every subscription you configure in the [azure](editconfig.html#15-azure-settings) section of `config.json`.

### 3.1. Create the Service Principal

Create the service principal with the [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) and assign the **Reader** role on the first subscription:
```
az login
az ad sp create-for-rbac --name hammer --role Reader --scopes /subscriptions/<subscription_id>
```
The command outputs `appId` (client ID), `password` (client secret) and `tenant` (tenant ID). Note them down for the [credentials](#5-put-azuregcp-credentials-into-dynamodb) step and keep the client secret out of source control.

### 3.2. Role Assignments

Assign the following [built-in roles](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles) to the service principal in **each** subscription:

| Role                              | Required for                                                                           |
|-----------------------------------|----------------------------------------------------------------------------------------|
| **Reader**                        | identification and reporting of all Azure issue types                                  |
| **Storage Account Contributor**   | remediation of `azure_storage_public_access` and `azure_storage_keys_rotation` issues   |
| **Network Contributor**           | remediation of `azure_nsg_unrestricted_access` issues                                  |

Example:
```
az role assignment create --assignee <appId> --role "Reader" --scope /subscriptions/<subscription_id>
az role assignment create --assignee <appId> --role "Storage Account Contributor" --scope /subscriptions/<subscription_id>
az role assignment create --assignee <appId> --role "Network Contributor" --scope /subscriptions/<subscription_id>
```

**Note**: remediation roles are required only for subscriptions listed in `remediation_accounts` (or all configured subscriptions if `remediation_accounts` is not set) of issue types with enabled remediation. You can also assign the roles at management group scope to cover several subscriptions.

## 4. Google Cloud Platform Prerequisites

**This step is required only if you intend to use GCP issue types** (check [multi-cloud overview](multicloud_overview.html)).

Dow Jones Hammer accesses GCP projects with a single **service account** that has IAM role bindings in every project you configure in the [gcp](editconfig.html#16-gcp-settings) section of `config.json`.

### 4.1. Create the Service Account

Create the service account in a project of your choice (`<sa_project_id>`), and enable the APIs used by Dow Jones Hammer in each checked project:
```
gcloud iam service-accounts create hammer --display-name "Dow Jones Hammer" --project <sa_project_id>
gcloud services enable compute.googleapis.com iam.googleapis.com storage.googleapis.com cloudresourcemanager.googleapis.com --project <project_id>
```

### 4.2. IAM Roles

Grant the following [IAM roles](https://cloud.google.com/iam/docs/understanding-roles) to `hammer@<sa_project_id>.iam.gserviceaccount.com` in **each** project:

| Role                                                | Required for                                                    |
|-----------------------------------------------------|-----------------------------------------------------------------|
| **Viewer** (`roles/viewer`)                         | identification and reporting of all GCP issue types             |
| **Security Reviewer** (`roles/iam.securityReviewer`)| identification of `gcp_bucket_public_access` issues (bucket IAM policies) and other IAM policies |
| **Storage Admin** (`roles/storage.admin`)           | remediation of `gcp_bucket_public_access` issues                |
| **Compute Security Admin** (`roles/compute.securityAdmin`) | remediation of `gcp_firewall_unrestricted_access` issues |
| **Service Account Key Admin** (`roles/iam.serviceAccountKeyAdmin`) | remediation of `gcp_sa_keys_rotation` issues     |

Example:
```
SA=hammer@<sa_project_id>.iam.gserviceaccount.com
for role in roles/viewer roles/iam.securityReviewer roles/storage.admin roles/compute.securityAdmin roles/iam.serviceAccountKeyAdmin; do
    gcloud projects add-iam-policy-binding <project_id> --member "serviceAccount:${SA}" --role "${role}"
done
```

**Note**: remediation roles are required only for projects where remediation of the corresponding issue type is enabled. You can also grant the roles at folder or organization level.

### 4.3. Create the Service Account Key

```
gcloud iam service-accounts keys create hammer-gcp-key.json --iam-account hammer@<sa_project_id>.iam.gserviceaccount.com
```

**Note**: the key created here is a user-managed service account key, so `gcp_sa_keys_rotation` will report it once it becomes older than `rotation_criteria_days`. Rotate it regularly (and update DynamoDB), or [whitelist](editconfig.html) it.

## 5. Put Azure/GCP Credentials into DynamoDB

Azure and GCP credentials are stored in the `hammer-credentials` DynamoDB table (`<ResourcesPrefix>credentials`), which is created by the [DynamoDB tables](deployment_cloudformation.html#312-dynamodb-tables) stack and encrypted at rest. Every item has the `service` key (`azure` or `gcp`) and the `credentials` map. Run the commands below after deploying the DynamoDB tables, in the master AWS account and the region where Dow Jones Hammer is deployed.

**Azure** (`service` = `azure`): create a temporary `azure-item.json` file outside of the Dow Jones Hammer sources:
```
{
    "service": {"S": "azure"},
    "credentials": {"M": {
        "tenant_id": {"S": "<tenant>"},
        "client_id": {"S": "<appId>"},
        "client_secret": {"S": "<password>"}
    }}
}
```
and put it to DynamoDB:
```
aws dynamodb put-item --table-name hammer-credentials --item file://azure-item.json
rm azure-item.json
```

**GCP** (`service` = `gcp`): convert the service account JSON key to a DynamoDB item with [jq](https://stedolan.github.io/jq/) and put it to DynamoDB:
```
jq '{service: {S: "gcp"}, credentials: {M: (with_entries(.value = {S: (.value | tostring)}))}}' hammer-gcp-key.json > gcp-item.json
aws dynamodb put-item --table-name hammer-credentials --item file://gcp-item.json
rm gcp-item.json hammer-gcp-key.json
```

To verify that the items exist without printing the secrets:
```
aws dynamodb scan --table-name hammer-credentials --projection-expression "service"
```

**Note**: `put-item` replaces the whole item, so use the same commands to rotate the Azure client secret or the GCP service account key.
