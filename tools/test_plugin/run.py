# tools/test_plugin/run.py
#
# Throwaway plugin — not a real scan, just echoes back whatever it received
# so you can confirm the mechanism (dashboard -> job -> agent -> plugin ->
# result) works end to end. Safe to delete once you've confirmed that.

import datetime


def execute(target: str, profile: str, **kwargs) -> dict:
    return {
        "echo_test": True,
        "target": target,
        "profile": profile,
        "received_extra_params": kwargs,
        "executed_at": datetime.datetime.utcnow().isoformat(),
        "note": "This is the throwaway echo_test plugin from tools/test_plugin/ — "
                "it doesn't scan anything. If you're seeing this in a result, the "
                "full plugin mechanism (dashboard -> job -> agent -> plugin -> "
                "result) is working end to end.",
    }
