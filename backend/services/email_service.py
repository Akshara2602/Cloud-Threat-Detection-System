
import os
import json
import boto3

from botocore.exceptions import (
    ClientError,
    BotoCoreError,
    PartialCredentialsError,
    NoCredentialsError
)


class EmailNotificationService:

    def __init__(self):
        self.region = os.getenv("AWS_REGION", "ap-south-1")
        self.topic_arn = os.getenv("SNS_TOPIC_ARN")

    def send_alert(self, alert):

        if not self.topic_arn:
            return {
                "success": False,
                "message": "SNS_TOPIC_ARN is not configured"
            }

        access_key = os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")

        if not access_key or not secret_key:
            return {
                "success": False,
                "message": "AWS credentials are missing or incomplete"
            }

        try:
            client = boto3.client(
                "sns",
                region_name=self.region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )

            message = {
                "threat_type": alert.get("threat_type"),
                "description": alert.get("description"),
                "severity": alert.get("severity"),
                "risk_score": alert.get("risk_score"),
                "source_ip": alert.get("source_ip"),
                "event_name": alert.get("event_name"),
                "timestamp": alert.get("timestamp")
            }

            response = client.publish(
                TopicArn=self.topic_arn,
                Subject="Cloud Security Alert - " + str(
                    alert.get("severity", "UNKNOWN")
                ),
                Message=json.dumps(message, indent=4)
            )

            return {
                "success": True,
                "message_id": response.get("MessageId")
            }

        except (
            PartialCredentialsError,
            NoCredentialsError,
            ClientError,
            BotoCoreError
        ) as error:

            return {
                "success": False,
                "message": str(error)
            }

        except Exception as error:
            return {
                "success": False,
                "message": str(error)
            }
