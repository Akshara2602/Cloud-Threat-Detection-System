
import ipaddress


KNOWN_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")
]


def analyze_ip(source_ip):

    try:

        ip = ipaddress.ip_address(source_ip)

        if ip.is_loopback:
            return {
                "valid": True,
                "classification": "LOOPBACK",
                "suspicious": False
            }

        if ip.is_private:

            return {
                "valid": True,
                "classification": "PRIVATE",
                "suspicious": False
            }

        if ip.is_global:

            return {
                "valid": True,
                "classification": "PUBLIC",
                "suspicious": False
            }

        return {
            "valid": True,
            "classification": "NON_GLOBAL",
            "suspicious": False
        }

    except ValueError:

        return {
            "valid": False,
            "classification": "INVALID",
            "suspicious": True
        }
