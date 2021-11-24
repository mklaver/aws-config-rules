#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Description: Check if any S3 bucket does not have a lifecycle policy enabled or that matches preconfigured settings.
#
# Trigger Type: Change Triggered
# Scope of Changes: S3:Bucket
# Accepted Parameters: None
# Your Lambda function execution role will need to have a policy that provides the appropriate
# permissions.  Here is a policy that you can consider.  You should validate this for your own
# environment
#{
#    "Version": "2012-10-17",
#    "Statement": [
#        {
#            "Effect": "Allow",
#            "Action": [
#                "logs:CreateLogGroup",
#                "logs:CreateLogStream",
#                "logs:PutLogEvents"
#            ],
#            "Resource": "arn:aws:logs:*:*:*"
#        },
#       {
#            "Effect": "Allow",
#            "Action": [
#                "config:PutEvaluations"
#            ],
#            "Resource": "*"
#        }
#    ]
#}
#

import json
import logging
import boto3

log = logging.getLogger()
log.setLevel(logging.DEBUG)
APPLICABLE_RESOURCES = ["AWS::S3::Bucket"]


def evaluate_compliance(configuration_item):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
        }

    if configuration_item["configurationItemStatus"] == "ResourceDeleted":
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The configurationItem was deleted " +
                          "and therefore cannot be validated"
        }
    
    # Get the lifecycle rules from the configuration item passed in the trigger
    lifecycle_rules = configuration_item["supplementaryConfiguration"].get("BucketLifecycleConfiguration")\
        .get("rules") if "BucketLifecycleConfiguration" in configuration_item["supplementaryConfiguration"] \
        else None
    
    # Set the expected transition timeframe as well as the expected transition storage class
    days = 30
    storage_class = "GLACIER"
    if lifecycle_rules is None:
        return {
            "compliance_type": "NON_COMPLIANT",
            "annotation": f"Bucket Lifecycle Rule(s) do not match specified timeframe({days}) or storage class"
                          f"({storage_class}). The current lifecycle rule is: None."
        }
    else:
        for rule in lifecycle_rules:
            if "transitions" in rule:
                for transitions in rule.get("transitions"):
                    if transitions["days"] is not days or transitions["storageClass"] != storage_class:
                        return {
                            "compliance_type": "NON_COMPLIANT",
                            "annotation": f"Bucket Lifecycle Rule(s) do not match specified timeframe({days}) or "
                                          f"storage class ({storage_class}). The current lifecycle rule is: "
                                          f"{transitions['days']} days & storage class {transitions['storage_class']}."
                        }
    return {
        "compliance_type": "COMPLIANT",
        "annotation": f"Bucket Lifecycle rule exists and matches the specified timeframe ({days}) and storage"
        f" class ({storage_class}). "
    }


def lambda_handler(event, context):
    log.debug("Event %s", event)
    invoking_event      = json.loads(event["invokingEvent"])
    configuration_item  = invoking_event["configurationItem"]
    evaluation          = evaluate_compliance(configuration_item)
    config              = boto3.client("config")

    config.put_evaluations(
       Evaluations=[
           {
               "ComplianceResourceType":    invoking_event["configurationItem"]["resourceType"],
               "ComplianceResourceId":      invoking_event["configurationItem"]["resourceId"],
               "ComplianceType":            evaluation["compliance_type"],
               "Annotation":                evaluation["annotation"],
               "OrderingTimestamp":         invoking_event["configurationItem"]["configurationItemCaptureTime"]
           },
       ],
       ResultToken=event["resultToken"])
