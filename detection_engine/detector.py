
from detection_engine.rules import (
    is_suspicious_event,
    get_event_description
)

from detection_engine.classifier import classify_threat

from detection_engine.risk_score import (
    calculate_risk_score,
    get_risk_level
)

from detection_engine.brute_force import (
    BruteForceDetector
)

from detection_engine.iam_analyzer import (
    analyze_iam_event
)

from detection_engine.ip_analyzer import (
    analyze_ip
)


class CloudThreatDetector:

    def __init__(self):

        self.brute_force = BruteForceDetector(
            threshold=5,
            time_window_minutes=10
        )

    def normalize_event(self, event):

        detail = event.get("detail", {})

        if not isinstance(detail, dict):
            detail = {}

        normalized = dict(detail)

        normalized["id"] = event.get("id")

        normalized["source"] = event.get(
            "source",
            detail.get("eventSource", "")
        )

        normalized["detail-type"] = event.get(
            "detail-type",
            ""
        )

        normalized["eventName"] = detail.get(
            "eventName",
            event.get("eventName", "")
        )

        normalized["sourceIPAddress"] = detail.get(
            "sourceIPAddress",
            event.get("sourceIPAddress", "")
        )

        normalized["userIdentity"] = detail.get(
            "userIdentity",
            event.get("userIdentity", {})
        )

        normalized["awsRegion"] = event.get(
            "region",
            detail.get("awsRegion", "")
        )

        normalized["responseElements"] = detail.get(
            "responseElements",
            event.get("responseElements")
        )

        normalized["errorCode"] = detail.get(
            "errorCode",
            event.get("errorCode")
        )

        normalized["requestParameters"] = detail.get(
            "requestParameters",
            event.get("requestParameters", {})
        )

        return normalized

    def analyze_event(self, event):

        normalized = self.normalize_event(event)

        event_name = normalized.get("eventName", "")

        source_ip = normalized.get("sourceIPAddress", "")

        alerts = []

        # GuardDuty finding detection
        if event.get("source") == "aws.guardduty":

            finding = event.get("detail", {})

            finding_severity = finding.get(
                "severity", 0
            )

            if finding_severity >= 8:
                severity = "CRITICAL"

            elif finding_severity >= 6:
                severity = "HIGH"

            elif finding_severity >= 4:
                severity = "MEDIUM"

            else:
                severity = "LOW"

            finding_type = finding.get(
                "type",
                "UNKNOWN_GUARDDUTY_FINDING"
            )

            if severity != "LOW":

                alerts.append({
                    "threat_type": finding_type,
                    "description": finding.get(
                        "description",
                        "GuardDuty security finding detected."
                    ),
                    "severity": severity
                })

        # CloudTrail event detection
        else:

            severity = classify_threat(normalized)

            # General suspicious event detection
            if is_suspicious_event(event_name):

                alerts.append({
                    "threat_type": event_name,
                    "description": get_event_description(
                        event_name
                    ),
                    "severity": severity
                })

            # IAM detection only when general rules
            # have not already detected the event
            else:

                iam_result = analyze_iam_event(normalized)

                if iam_result["is_risky"]:

                    alerts.append({
                        "threat_type": "IAM_SECURITY_RISK",
                        "description": iam_result["message"],
                        "severity": iam_result["severity"]
                    })

            # Failed login detection
            if event_name == "ConsoleLogin":

                login_failed = (
                    normalized.get("errorCode") is not None
                )

                if login_failed and source_ip:

                    detected = self.brute_force.record_attempt(
                        source_ip
                    )

                    if detected:

                        alerts.append({
                            "threat_type": "BRUTE_FORCE",
                            "description": (
                                "Repeated failed login "
                                "attempts detected."
                            ),
                            "severity": "HIGH"
                        })

        # IP analysis
        ip_result = analyze_ip(source_ip) if source_ip else {
            "suspicious": False
        }

        results = []

        # Calculate risk scores
        for alert in alerts:

            score = calculate_risk_score(
                severity=alert["severity"],
                suspicious_ip=ip_result["suspicious"]
            )

            results.append({
                **alert,

                "risk_score": score,

                "risk_level": get_risk_level(score),

                "source_ip": source_ip,

                "event_name": event_name,

                "user_identity": normalized.get(
                    "userIdentity", {}
                ).get("arn", "Unknown"),

                "region": normalized.get(
                    "awsRegion", "Unknown"
                )
            })

        return results
