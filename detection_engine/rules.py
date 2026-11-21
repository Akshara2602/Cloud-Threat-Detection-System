
# Cloud Threat Detection System
# Security Detection Rules

CRITICAL_EVENTS = [
    "ConsoleLoginRoot",
    "StopLogging",
    "DeleteTrail",
    "DeleteDetector"
]

HIGH_RISK_EVENTS = [
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "AuthorizeSecurityGroupIngress",
    "CreateLoginProfile",
    "UpdateAssumeRolePolicy"
]

MEDIUM_RISK_EVENTS = [
    "CreateAccessKey",
    "CreateUser",
    "CreateRole",
    "CreatePolicy",
    "RunInstances"
]

LOW_RISK_EVENTS = [
    "DescribeInstances",
    "ListUsers",
    "ListBuckets"
]

SUSPICIOUS_EVENT_NAMES = (
    CRITICAL_EVENTS +
    HIGH_RISK_EVENTS +
    MEDIUM_RISK_EVENTS
)

def get_event_severity(event_name):

    if event_name in CRITICAL_EVENTS:
        return "CRITICAL"

    if event_name in HIGH_RISK_EVENTS:
        return "HIGH"

    if event_name in MEDIUM_RISK_EVENTS:
        return "MEDIUM"

    if event_name in LOW_RISK_EVENTS:
        return "LOW"

    return "LOW"


def is_suspicious_event(event_name):

    return event_name in SUSPICIOUS_EVENT_NAMES


def get_event_description(event_name):

    descriptions = {

        "ConsoleLoginRoot":
        "Root account activity detected.",

        "StopLogging":
        "CloudTrail logging was disabled.",

        "DeleteTrail":
        "A CloudTrail trail was deleted.",

        "DeleteDetector":
        "GuardDuty detector deletion detected.",

        "AttachUserPolicy":
        "An IAM policy was attached to a user.",

        "AttachRolePolicy":
        "An IAM policy was attached to a role.",

        "PutUserPolicy":
        "A user policy was modified.",

        "PutRolePolicy":
        "A role policy was modified.",

        "AuthorizeSecurityGroupIngress":
        "An inbound security group rule was modified.",

        "CreateLoginProfile":
        "A new IAM console login profile was created.",

        "UpdateAssumeRolePolicy":
        "A role trust policy was modified.",

        "CreateAccessKey":
        "A new access key was created.",

        "CreateUser":
        "A new IAM user was created.",

        "CreateRole":
        "A new IAM role was created.",

        "CreatePolicy":
        "A new IAM policy was created.",

        "RunInstances":
        "An EC2 instance was launched."
    }

    return descriptions.get(
        event_name,
        "Suspicious cloud activity detected."
    )
