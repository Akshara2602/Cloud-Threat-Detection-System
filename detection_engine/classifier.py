
from detection_engine.rules import get_event_severity

def classify_threat(event):

    event_name = event.get("eventName", "")

    if event.get("source") == "aws.guardduty":

        severity = event.get(
            "detail", {}
        ).get("severity", 0)

        if severity >= 8:
            return "CRITICAL"

        elif severity >= 6:
            return "HIGH"

        elif severity >= 4:
            return "MEDIUM"

        return "LOW"

    if event_name == "ConsoleLogin":

        response = event.get(
            "responseElements"
        )

        if response is None:
            return "HIGH"

    return get_event_severity(event_name)
