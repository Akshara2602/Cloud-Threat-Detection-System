
import requests
import json
import uuid
import time

API_URL = "http://127.0.0.1:5000"

API_SECRET = "MyCloudProjectSecret2026!"


HEADERS = {

    "Content-Type": "application/json",

    "X-API-KEY": API_SECRET

}


def send_event(event):

    response = requests.post(

        API_URL + "/api/events/ingest",

        json=event,

        headers=HEADERS,

        timeout=15

    )

    print("Status:", response.status_code)

    print("Response:", response.text)


def generate_root_login():

    return {

        "id": str(uuid.uuid4()),

        "source": "aws.signin",

        "detail-type": "AWS API Call via CloudTrail",

        "region": "ap-south-1",

        "detail": {

            "eventName": "ConsoleLogin",

            "eventSource": "signin.amazonaws.com",

            "sourceIPAddress": "198.51.100.10",

            "userIdentity": {

                "arn": "arn:aws:iam::123456789012:root"

            },

            "errorCode": None,

            "responseElements": {

                "ConsoleLogin": "Success"

            }

        }

    }


def generate_iam_policy_change():

    return {

        "id": str(uuid.uuid4()),

        "source": "aws.iam",

        "detail-type": "AWS API Call via CloudTrail",

        "region": "ap-south-1",

        "detail": {

            "eventName": "AttachUserPolicy",

            "eventSource": "iam.amazonaws.com",

            "sourceIPAddress": "203.0.113.15",

            "userIdentity": {

                "arn": "arn:aws:iam::123456789012:user/demo"

            },

            "requestParameters": {

                "userName": "demo-user"

            }

        }

    }


def generate_security_group_change():

    return {

        "id": str(uuid.uuid4()),

        "source": "aws.ec2",

        "detail-type": "AWS API Call via CloudTrail",

        "region": "ap-south-1",

        "detail": {

            "eventName": "AuthorizeSecurityGroupIngress",

            "eventSource": "ec2.amazonaws.com",

            "sourceIPAddress": "203.0.113.20",

            "userIdentity": {

                "arn": "arn:aws:iam::123456789012:user/admin"

            },

            "requestParameters": {

                "groupId": "sg-demo123"

            }

        }

    }


def generate_guardduty_finding():

    return {

        "id": str(uuid.uuid4()),

        "source": "aws.guardduty",

        "detail-type": "GuardDuty Finding",

        "region": "ap-south-1",

        "detail": {

            "type": "UnauthorizedAccess:IAMUser/ConsoleLogin",

            "severity": 8,

            "description": (
                "Simulated suspicious console login finding"
            ),

            "accountId": "123456789012"

        }

    }


def main():

    events = [
    generate_root_login(),
    generate_iam_policy_change(),
    generate_security_group_change()
]

    for event in events:

        print("\nSending event:")

        print(
            json.dumps(
                event,
                indent=4
            )
        )

        send_event(event)

        time.sleep(2)


if __name__ == "__main__":

    main()
