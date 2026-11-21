import os
import json
import boto3

from botocore.exceptions import ClientError


class EmailNotificationService:

    def __init__(self):

        self.region = os.getenv(
            "AWS_REGION",
            "ap-south-1"
        )

        self.topic_arn = os.getenv(
            "SNS_TOPIC_ARN"
        )

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

            "alert_type": alert["threat_type"],

            "severity": alert["severity"],

            "risk_score": alert["risk_score"],

            "source_ip": alert["source_ip"],

            "description": alert["description"],

            "timestamp": str(alert.get("timestamp", ""))
        }

        try:

            response = self.client.publish(

                TopicArn=self.topic_arn,

                Subject=(
                    "Cloud Security Alert - "
                    + alert["severity"]
                ),

                Message=json.dumps(
                    message,
                    indent=4
                )
            )

            return {
                "success": True,
                "message_id": response["MessageId"]
            }

        except ClientError as error:

            return {
                "success": False,
                "message": str(error)
            }