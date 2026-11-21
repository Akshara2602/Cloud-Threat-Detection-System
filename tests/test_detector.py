from detection_engine.detector import (
    CloudThreatDetector
)


def test_iam_policy_detection():

    detector = CloudThreatDetector()

    event = {

        "eventName": "AttachUserPolicy",

        "sourceIPAddress": "203.0.113.10",

        "userIdentity": {

            "arn": "arn:aws:iam::123456789012:user/test"

        }

    }

    alerts = detector.analyze_event(event)

    assert len(alerts) > 0

    assert any(
        alert["severity"] == "HIGH"
        for alert in alerts
    )


def test_guardduty_detection():

    detector = CloudThreatDetector()

    event = {

        "id": "finding-test-001",

        "source": "aws.guardduty",

        "detail-type": "GuardDuty Finding",

        "detail": {

            "severity": 8,

            "type": "UnauthorizedAccess:IAMUser/ConsoleLogin",

            "description": "Test finding"

        }

    }

    alerts = detector.analyze_event(event)

    assert len(alerts) == 1

    assert alerts[0]["severity"] == "CRITICAL"


def test_normal_activity():

    detector = CloudThreatDetector()

    event = {

        "eventName": "DescribeInstances",

        "sourceIPAddress": "192.168.1.10",

        "userIdentity": {

            "arn": "test-user"

        }

    }

    alerts = detector.analyze_event(event)

    assert len(alerts) == 0