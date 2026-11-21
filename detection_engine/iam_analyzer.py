
DANGEROUS_IAM_ACTIONS = [
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateAssumeRolePolicy",
    "DeleteUserPolicy"
]


def analyze_iam_event(event):

    event_name = event.get("eventName", "")

    if event_name in DANGEROUS_IAM_ACTIONS:

        return {
            "is_risky": True,
            "event": event_name,
            "message": (
                "Sensitive IAM modification detected."
            ),
            "severity": "HIGH"
        }

    return {
        "is_risky": False,
        "event": event_name,
        "message": "No risky IAM modification detected.",
        "severity": "LOW"
    }
