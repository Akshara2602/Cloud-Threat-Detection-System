
import os
import json
import logging
import boto3

from botocore.exceptions import (
    ClientError,
    BotoCoreError,
    PartialCredentialsError,
    NoCredentialsError
)

logger = logging.getLogger(__name__)


class EmailNotificationService:

    def __init__(self):
        self.region = os.getenv("AWS_REGION", "ap-south-1").strip()
        self.topic_arn = os.getenv("SNS_TOPIC_ARN", "").strip()

    def send_alert(self, alert):

        # 1. Check SNS topic configuration
        if not self.topic_arn:
            return {
                "success": False,
                "message": "SNS_TOPIC_ARN is missing or empty"
            }

        # 2. Read AWS credentials
        access_key = os.getenv("AWS_ACCESS_KEY_ID", "").strip()
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", "").strip()
        session_token = os.getenv("AWS_SESSION_TOKEN", "").strip()

        # 3. Validate credentials
        missing = []

        if not access_key:
            missing.append("AWS_ACCESS_KEY_ID")

        if not secret_key:
            missing.append("AWS_SECRET_ACCESS_KEY")

        if missing:
            return {
                "success": False,
                "message": "Missing or empty environment variables: "
                           + ", ".join(missing)
            }

        try:
            # 4. Create SNS client only when sending an alert
            client_options = {
                "service_name": "sns",
                "region_name": self.region,
                "aws_access_key_id": access_key,
                "aws_secret_access_key": secret_key
            }

            if session_token:
                client_options["aws_session_token"] = session_token

            client = boto3.client(**client_options)

            # 5. Prepare notification message
            message = {
                "threat_type": alert.get("threat_type"),
                "description": alert.get("description"),
                "severity": alert.get("severity"),
                "risk_score": alert.get("risk_score"),
                "source_ip": alert.get("source_ip"),
                "event_name": alert.get("event_name"),
                "timestamp": alert.get("timestamp")
            }

            # 6. Publish notification to SNS
            response = client.publish(
                TopicArn=self.topic_arn,
                Subject="Cloud Security Alert - " + str(
                    alert.get("severity", "UNKNOWN")
                ),
                Message=json.dumps(message, indent=4, default=str)
            )

            logger.info("SNS notification published successfully")

            return {
                "success": True,
                "message": "SNS notification published successfully",
                "message_id": response.get("MessageId")
            }

        except PartialCredentialsError:
            logger.exception("Incomplete AWS credentials")
            return {
                "success": False,
                "message": "AWS credentials are incomplete"
            }

        except NoCredentialsError:
            logger.exception("AWS credentials not found")
            return {
                "success": False,
                "message": "AWS credentials not found"
            }

        except ClientError as error:
            error_code = error.response.get(
                "Error", {}
            ).get("Code", "Unknown")

            logger.exception("SNS service returned an error")

            return {
                "success": False,
                "message": "SNS error: " + error_code
            }

        except BotoCoreError:
            logger.exception("AWS SDK error")
            return {
                "success": False,
                "message": "AWS SDK connection or configuration error"
            }

        except Exception:
            logger.exception("Unexpected notification error")
            return {
                "success": False,
                "message": "Unexpected error while sending SNS notification"
            }
