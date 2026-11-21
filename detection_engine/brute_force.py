
from collections import defaultdict
from datetime import datetime, timedelta


class BruteForceDetector:

    def __init__(
        self,
        threshold=5,
        time_window_minutes=10
    ):

        self.threshold = threshold

        self.time_window = timedelta(
            minutes=time_window_minutes
        )

        self.failed_attempts = defaultdict(list)


    def record_attempt(self, source_ip, timestamp=None):

        if not source_ip:
            return False

        timestamp = timestamp or datetime.utcnow()

        attempts = self.failed_attempts[source_ip]

        attempts.append(timestamp)

        cutoff = timestamp - self.time_window

        self.failed_attempts[source_ip] = [
            attempt
            for attempt in attempts
            if attempt >= cutoff
        ]

        return (
            len(self.failed_attempts[source_ip])
            >= self.threshold
        )


    def get_attempt_count(self, source_ip):

        return len(
            self.failed_attempts.get(source_ip, [])
        )
