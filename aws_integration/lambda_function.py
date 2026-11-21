import os
import json
import urllib.request
import urllib.error


API_URL = os.environ["API_URL"]

API_SECRET = os.environ["API_SECRET"]


def lambda_handler(event, context):

    print("Received AWS security event")

    event_source = event.get("source")

    detail_type = event.get("detail-type")

    if event_source == "aws.guardduty":

        finding = event.get("detail", {})

        print(
            "GuardDuty finding:",
            finding.get("type")
        )

    elif detail_type == "AWS API Call via CloudTrail":

        print(
            "CloudTrail activity:",
            event.get("detail", {}).get("eventName")
        )

    payload = json.dumps(event).encode("utf-8")

    request = urllib.request.Request(

        API_URL + "/api/events/ingest",

        data=payload,

        headers={

            "Content-Type": "application/json",

            "X-API-KEY": API_SECRET

        },

        method="POST"

    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=15
        ) as response:

            response_data = response.read().decode()

            print("Backend response:", response_data)

            return {

                "statusCode": response.status,

                "body": response_data

            }

    except urllib.error.HTTPError as error:

        print("HTTP error:", error.code)

        raise

    except Exception as error:

        print("Event processing failed:", str(error))

        raise