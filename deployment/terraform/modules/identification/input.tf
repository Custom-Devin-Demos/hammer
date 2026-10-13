variable "identificationCheckRateExpression" {}
variable "s3bucket" {}
variable "identificationIAMRole" {}
variable "lambdaSubnets" {}
variable "lambdaSecurityGroups" {}
variable "multiCloudLambdaRuntime" {
    default = "python3.9"
}

variable "resources-prefix" {}

variable "tags" {
    type = "map"
    default = {}
}