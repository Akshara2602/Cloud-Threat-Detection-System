
import os
import boto3
from dotenv import load_dotenv

load_dotenv()

region = os.getenv("AWS_REGION")
topic_arn = os.getenv("SNS_TOPIC_ARN")

try:
    sns = boto3.client("sns", region_name=region)

    response = sns.publish(
        TopicArn=topic_arn,
        Subject="Cloud Threat Detection - Test Email",
        Message="SNS email test successful. Your AWS notification setup is working."
    )

    print("SUCCESS: SNS accepted the message.")
    print("Message ID:", response["MessageId"])

except Exception as e:
    print("FAILED:", str(e))
