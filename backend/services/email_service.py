
import os
import json
import logging
import boto3

from dotenv import load_dotenv
from botocore.exceptions import ClientError, BotoCoreError

# Load environment variables from the project .env file
load_dotenv()

logger = logging.getLogger(__name__)


class EmailNotificationService:

    def __init__(self):
        self.region = os.getenv("AWS_REGION", "ap-south-1").strip()
        self.topic_arn = os.getenv("SNS_TOPIC_ARN", "").strip()

    def send_alert(self, alert):

        # Check SNS topic
        if not self.topic_arn:
            return {
                "success": False,
                "message": "SNS_TOPIC_ARN is missing from .env"
            }

        # Read AWS credentials
        access_key = os.getenv("AWS_ACCESS_KEY_ID", "").strip()
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", "").strip()

        try:
            # Create AWS SNS client
            if access_key and secret_key:
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=self.region
                )
            else:
                # Use the standard AWS credential chain
                session = boto3.Session(region_name=self.region)

            client = session.client("sns")

            # Prepare security alert
            message = {
                "Threat Type": alert.get("threat_type", "Unknown"),
                "Description": alert.get("description", "No description"),
                "Severity": alert.get("severity", "UNKNOWN"),
                "Risk Score": alert.get("risk_score", 0),
                "Source IP": alert.get("source_ip", "Unknown"),
                "Affected Resource": alert.get(
                    "event_name",
                    alert.get("affected_resource", "Unknown")
                ),
                "Timestamp": alert.get("timestamp", "Unknown")
            }

            # Publish email notification
            response = client.publish(
                TopicArn=self.topic_arn,
                Subject="Cloud Security Alert - " + str(
                    message["Severity"]
                ),
                Message=json.dumps(message, indent=4, default=str)
            )

            logger.info("SNS notification accepted: %s",
                        response.get("MessageId"))

            return {
                "success": True,
                "message": "SNS accepted the notification",
                "message_id": response.get("MessageId")
            }

        except ClientError as error:
            error_code = error.response.get(
                "Error", {}
            ).get("Code", "Unknown")

            logger.exception("SNS publishing failed")

            return {
                "success": False,
                "message": f"SNS error: {error_code}"
            }

        except BotoCoreError:
            logger.exception("AWS connection or credential error")

            return {
                "success": False,
                "message": "AWS credentials or connection error"
            }

        except Exception:
            logger.exception("Unexpected email notification error")

            return {
                "success": False,
                "message": "Unexpected notification error"
            }
