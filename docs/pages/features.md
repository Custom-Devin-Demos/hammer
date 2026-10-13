---
title: Security Features
keywords: overview
sidebar: mydoc_sidebar
permalink: features.html
---

Dow Jones Hammer can identify and report the following issues:

|Name                                                              |Description                                            |Default Alert Trigger                                                           |
|------------------------------------------------------------------|-------------------------------------------------------|--------------------------------------------------------------------------------|
|[S3 ACL Public Access](playbook1_s3_public_buckets_acl.html)      |Detects publicly accessible by ACL S3 buckets          |Any of the S3 buckets is worldwide accessible by ACL                            |
|[Insecure Services](playbook2_insecure_services.html)             |Detects groups with worldwide open ports from the list |Any of security groups allows unrestricted access to the ports defined in the configuration file|
|[IAM User Inactive Keys](playbook3_inactive_user_keys.html)       |Detects unused for N days access keys                  |Any of access keys is not used for the timeframe defined in the configuration file              |
|[IAM User Keys Rotation](playbook4_keysrotation.html)             |Detects the lack of access keys rotation for N days    |Any of access keys was created earlier than the timeframe defined in the configuration file     |
|[S3 Policy Public Access](playbook5_s3_public_buckets_policy.html)|Detects publicly accessible by policy S3 buckets       |Any of the S3 buckets is worldwide accessible by policy                         |
|[CloudTrail Logging Issues](playbook6_cloudtrail.html)            |Detects CloudTrail logging status and permission issues|Any of AWS regions does not have CloudTrail logging enabled or has access issues|
|[EBS Unencrypted Volumes](playbook7_ebs_unencrypted_volumes.html) |Detects not encrypted at rest EBS volumes              |Any of the EBS volumes is not encrypted at rest                                 |
|[EBS Public Snapshots](playbook8_ebs_snapshots_public.html)       |Detects publicly accessible EBS snapshots              |Any one of EBS snapshots is worldwide accessible                                |
|[RDS Public Snapshots](playbook9_rds_snapshots_public.html)       |Detects publicly accessible RDS snapshots              |Any one of RDS snapshots is worldwide accessible                                |
|[SQS Policy Public Access](playbook10_sqs_public_policy.html)     |Detects publicly accessible SQS policy                 |Any of SQS queues is worldwide accessible by policy                             |
|[S3 Unencrypted Buckets](playbook11_s3_unencryption.html)         |Detects not encrypted at reset S3 buckets              |Any of S3 bucket is not encrypted at rest                                       |
|[RDS Unencrypted instances](playbook12_rds_unencryption.html)     |Detects not encrypted at rest RDS instances            |Any one of RDS instances is not encrypted at reset                              |
|[AMIs public access](playbook13_amis_public_access.html)     |Detects publicly accessible AMIs            |Any one of AMI is worldwide accessible                             |
|[Azure Storage Public Access](playbook14_azure_storage_public_access.html)|Detects Azure storage accounts with public containers|Any of the storage accounts allows public blob access and has `Blob`/`Container` level containers|
|[Azure NSG Unrestricted Access](playbook15_azure_nsg_unrestricted_access.html)|Detects NSGs with Internet-open ports from the list|Any of network security groups allows inbound access from the Internet to the ports defined in the configuration file|
|[Azure Unencrypted Disks](playbook16_azure_unencrypted_disks.html)|Detects managed disks without CMK/ADE encryption|Any of the managed disks is encrypted with platform-managed keys only|
|[Azure Storage Keys Rotation](playbook17_azure_storage_keys_rotation.html)|Detects the lack of storage account keys rotation for N days|Any of storage account keys was created earlier than the timeframe defined in the configuration file|
|[GCP Bucket Public Access](playbook18_gcp_bucket_public_access.html)|Detects publicly accessible Cloud Storage buckets|Any of the buckets grants access to `allUsers`/`allAuthenticatedUsers`|
|[GCP Firewall Unrestricted Access](playbook19_gcp_firewall_unrestricted_access.html)|Detects firewall rules with worldwide open ports from the list|Any of ingress firewall rules allows access from `0.0.0.0/0`/`::/0` to the ports defined in the configuration file|
|[GCP Unencrypted Disks](playbook20_gcp_unencrypted_disks.html)|Detects disks without customer-managed encryption|Any of the disks is encrypted with Google-managed keys only|
|[GCP Service Account Keys Rotation](playbook21_gcp_sa_keys_rotation.html)|Detects the lack of service account keys rotation for N days|Any of user-managed service account keys was created earlier than the timeframe defined in the configuration file|

Dow Jones Hammer can perform remediation for all issues [except](remediation_backup_rollback.html#1-overview) **EBS Unencrypted volumes**, **CloudTrail Logging Issues**, **RDS Unencrypted instances**, **Azure Unencrypted Disks** and **GCP Unencrypted Disks**.

Azure and GCP issue types are described in the [multi-cloud overview](multicloud_overview.html).