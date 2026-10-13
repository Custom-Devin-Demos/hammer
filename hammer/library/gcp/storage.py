import logging


from datetime import datetime, timezone
from google.api_core.exceptions import GoogleAPIError, Forbidden, NotFound
from google.cloud import storage
from library.aws.s3 import S3Operations


# IAM members / ACL entities which make bucket public
PUBLIC_MEMBERS = ["allUsers", "allAuthenticatedUsers"]


class GCPStorageOperations(object):
    @staticmethod
    def get_public_bindings(bindings):
        """
        Walk through bucket IAM policy bindings and collect public members.

        :param bindings: list of bucket IAM policy bindings (dicts with `role` and `members` keys, as GCP returns)

        :return: dict with public bindings {role: [public members]}
        """
        public_bindings = {}
        for binding in bindings or []:
            public = sorted(set(member for member in binding.get("members", []) if member in PUBLIC_MEMBERS))
            if public:
                role = binding["role"]
                public_bindings[role] = sorted(set(public_bindings.get(role, []) + public))
        return public_bindings

    @staticmethod
    def restrict_bindings(bindings):
        """
        Remove public members from bucket IAM policy bindings.
        It does not modify supplied bindings, but creates new list.

        :param bindings: list of bucket IAM policy bindings (as GCP returns)

        :return: new list with bindings without public members (bindings without members are dropped)
        """
        restricted = []
        for binding in bindings or []:
            members = [member for member in binding.get("members", []) if member not in PUBLIC_MEMBERS]
            if members:
                new_binding = dict(binding)
                new_binding["members"] = members
                restricted.append(new_binding)
        return restricted

    @staticmethod
    def get_public_acls(acl):
        """
        Walk through legacy bucket ACL and collect public entries.

        :param acl: list of bucket ACL entries (dicts with `entity` and `role` keys, as GCP returns)

        :return: dict with public ACL entries {entity: [roles]}
        """
        public_acls = {}
        for entry in acl or []:
            entity = entry.get("entity")
            if entity in PUBLIC_MEMBERS:
                public_acls.setdefault(entity, []).append(entry.get("role"))
        return public_acls


class GCPBucket(object):
    """
    Basic class for GCP storage bucket.
    Encapsulates name/location/labels, IAM policy bindings and legacy ACL.
    """
    def __init__(self, account, source, bindings, acl=None, policy=None):
        """
        :param account: `GCPAccount` instance where bucket is present
        :param source: `google.cloud.storage.Bucket` instance
        :param bindings: list with bucket IAM policy bindings
        :param acl: list with bucket legacy ACL entries (None if uniform bucket-level access is enabled)
        :param policy: `google.api_core.iam.Policy` instance to use for restriction
        """
        self.account = account
        self.source = source
        self.name = source.name
        self.location = source.location
        self.tags = dict(source.labels or {})
        iam_configuration = source.iam_configuration
        self.uniform_access = bool(getattr(iam_configuration, "uniform_bucket_level_access_enabled", False))
        self.public_access_prevention = getattr(iam_configuration, "public_access_prevention", None)
        self.bindings = bindings or []
        self.acl = acl or []
        self._policy = policy

    @property
    def public_bindings(self):
        """ :return: dict with public IAM policy bindings {role: [members]} """
        return GCPStorageOperations.get_public_bindings(self.bindings)

    @property
    def public_acls(self):
        """ :return: dict with public legacy ACL entries {entity: [roles]} """
        if self.uniform_access:
            # legacy ACLs are not evaluated when uniform bucket-level access is enabled
            return {}
        return GCPStorageOperations.get_public_acls(self.acl)

    @property
    def public_access_prevention_enforced(self):
        """ :return: boolean, if public access prevention is enforced on bucket """
        return self.public_access_prevention == "enforced"

    @property
    def public(self):
        """
        :return: boolean, True - if bucket IAM policy or legacy ACL grants access to `allUsers`/`allAuthenticatedUsers`
                 (and public access prevention is not enforced, which blocks such access)
        """
        if self.public_access_prevention_enforced:
            return False
        return bool(self.public_bindings or self.public_acls)

    @property
    def backup_data(self):
        """ :return: dict with bucket IAM policy and ACL to backup """
        return {
            "project": self.account.id,
            "bucket": self.name,
            "bindings": self.bindings,
            "acl": self.acl,
            "uniform_bucket_level_access": self.uniform_access,
            "public_access_prevention": self.public_access_prevention,
        }

    def backup_s3(self, s3_client, bucket):
        """
        Backup bucket IAM policy bindings and ACL json to S3.

        :param s3_client: S3 boto3 client
        :param bucket: S3 bucket name where to put backup

        :return: S3 path (without bucket name) to saved object with backup
        """
        timestamp = datetime.now(timezone.utc).isoformat('T', 'seconds')
        path = (f"gcp_bucket_policies/"
                f"{self.account.id}/"
                f"{self.name}_{timestamp}.json")
        if S3Operations.object_exists(s3_client, bucket, path):
            raise Exception(f"s3://{bucket}/{path} already exists")
        S3Operations.put_object(s3_client, bucket, path, self.backup_data)
        return path

    def restrict(self, enforce_public_access_prevention=False):
        """
        Remove public members from bucket IAM policy and public entries from legacy ACL,
        optionally enforce public access prevention.

        :param enforce_public_access_prevention: boolean, if `public_access_prevention` should be set to `enforced`

        :return: boolean, if restriction was successful

        .. note:: This keeps bucket bindings/acl unchanged.
                  You need to recheck bucket to ensure that it was really restricted.
        """
        try:
            if self.public_bindings:
                policy = self._policy if self._policy is not None else \
                    self.source.get_iam_policy(requested_policy_version=3)
                policy.bindings = GCPStorageOperations.restrict_bindings(policy.bindings)
                self.source.set_iam_policy(policy)
            if self.public_acls:
                acl = [entry for entry in self.acl if entry.get("entity") not in PUBLIC_MEMBERS]
                self.source.acl.save(acl=acl)
            if enforce_public_access_prevention:
                self.source.iam_configuration.public_access_prevention = "enforced"
                self.source.patch()
        except Exception:
            logging.exception(f"Failed to restrict public access to {self.name} bucket in {self.account}")
            return False
        return True

    def __str__(self):
        return (f"{self.__class__.__name__}(Name={self.name}, Location={self.location}, "
                f"PublicBindings={self.public_bindings}, PublicACLs={self.public_acls})")


class GCPBucketsPublicAccessChecker(object):
    """
    Basic class for checking GCP storage buckets public access in project.
    Encapsulates discovered buckets.
    """
    def __init__(self, account):
        """
        :param account: `GCPAccount` instance with buckets to check
        """
        self.account = account
        self.buckets = []
        # names of buckets which failed to be evaluated (their issues must not be resolved)
        self.failed = []

    def get_bucket(self, name):
        """
        :return: `GCPBucket` by name
        """
        for bucket in self.buckets:
            if bucket.name == name:
                return bucket
        return None

    def check(self, ids=None, tags=None):
        """
        Walk through buckets in the project and put them to `self.buckets`.

        :param ids: list with bucket names to check, if it is not supplied - all buckets must be checked
        :param tags: dict with labels to filter buckets by ({key: value or [values]})

        :return: boolean. True - if check was successful,
                          False - otherwise
        """
        try:
            client = self.account.client(storage.Client, project=self.account.id)
            if ids:
                sources = []
                for name in ids:
                    try:
                        sources.append(client.get_bucket(name))
                    except NotFound:
                        logging.debug(f"Bucket {name} not found in {self.account}")
            else:
                sources = list(client.list_buckets())
        except Forbidden:
            logging.error(f"Access denied in {self.account} (storage.buckets.list)")
            return False
        except Exception:
            logging.exception(f"Failed to list buckets in {self.account}")
            return False

        for source in sources:
            if tags and not self.match_tags(source.labels or {}, tags):
                continue
            try:
                policy = source.get_iam_policy(requested_policy_version=3)
                bindings = [dict(binding) for binding in policy.bindings]
            except GoogleAPIError:
                logging.exception(f"Failed to get {source.name} bucket IAM policy in {self.account}")
                self.failed.append(source.name)
                continue

            acl = None
            iam_configuration = source.iam_configuration
            if not getattr(iam_configuration, "uniform_bucket_level_access_enabled", False):
                try:
                    source.acl.reload()
                    acl = [dict(entry) for entry in source.acl]
                except GoogleAPIError:
                    logging.exception(f"Failed to get {source.name} bucket ACL in {self.account}")

            bucket = GCPBucket(account=self.account,
                               source=source,
                               bindings=bindings,
                               acl=acl,
                               policy=policy)
            self.buckets.append(bucket)
        return True

    @staticmethod
    def match_tags(labels, tags):
        """
        :return: boolean, if bucket labels match all supplied tags
        """
        for key, value in tags.items():
            values = value if isinstance(value, list) else [value]
            if labels.get(key) not in values:
                return False
        return True
