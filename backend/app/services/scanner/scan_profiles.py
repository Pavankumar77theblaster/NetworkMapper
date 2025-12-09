"""Scan profile configurations for different scan types."""

SCAN_PROFILES = {
    "quick": {
        "ports": "1-100",
        "timing": "T4",
        "service_detection": False,
        "os_detection": False,
        "timeout": 60,
        "arguments": "-T4 --top-ports 100"
    },
    "standard": {
        "ports": "1-1000",
        "timing": "T3",
        "service_detection": True,
        "os_detection": False,
        "timeout": 300,
        "arguments": "-T3 --top-ports 1000 -sV"
    },
    "deep": {
        "ports": "1-65535",
        "timing": "T2",
        "service_detection": True,
        "os_detection": True,
        "timeout": 3600,
        "arguments": "-T2 -p- -sV -O"
    }
}


def get_scan_profile(profile_name: str) -> dict:
    """Get scan profile configuration by name."""
    return SCAN_PROFILES.get(profile_name, SCAN_PROFILES["standard"])
