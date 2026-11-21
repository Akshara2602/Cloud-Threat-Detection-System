
import os
import json
import boto3

from datetime import datetime
from botocore.exceptions import ClientError


class EmailNotificationService:

    def __init__(self):

        self.region = os.getenv(
            "AWS_REGION",
            "ap-south-1"
        )

        self.topic_arn = os.getenv("SNS_TOPIC_ARN")

        self.client = boto3.client(
            "sns",
            region_name=self.region
        )

    def send_alert(self, alert):

        if not self.topic_arn:
            return {
                "success": False,
                "message": "SNS topic not configured"
            }

        message = {
            "alert_type": alert.get("threat_type"),
            "severity": alert.get("severity"),
            "risk_score": alert.get("risk_score"),
            "source_ip": alert.get("source_ip"),
            "description": alert.get("description"),
            "timestamp": str(
                alert.get("timestamp", datetime.utcnow())
            )
        }

        try:

            response = self.client.publish(
                TopicArn=self.topic_arn,
                Subject=(
                    "Cloud Security Alert - "
                    + str(alert.get("severity", "UNKNOWN"))
                ),
                Message=json.dumps(message, indent=4)
            )

            return {
                "success": True,
                "message_id": response["MessageId"],
                "message": "SNS notification published"
            }

        except ClientError as error:

            return {
                "success": False,
                "message": str(error)
            }
