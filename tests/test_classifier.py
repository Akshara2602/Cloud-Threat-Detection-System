from detection_engine.classifier import (
    classify_threat
)


def test_critical_guardduty():

    event = {

        "source": "aws.guardduty",

        "detail": {

            "severity": 8

        }

    }

    assert classify_threat(event) == "CRITICAL"


def test_medium_guardduty():

    event = {

        "source": "aws.guardduty",

        "detail": {

            "severity": 5

        }

    }

    assert classify_threat(event) == "MEDIUM"


def test_iam_event():

    event = {

        "eventName": "AttachUserPolicy"

    }

    assert classify_threat(event) == "HIGH"