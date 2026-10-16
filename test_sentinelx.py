"""Beginner-friendly automated tests for SentinelX message validation.

Run from the folder containing app_upgraded.py:
    python -m unittest -v test_sentinelx.py

These tests read validate_message() from app_upgraded.py without launching
Streamlit or changing the SQLite event database.
"""
import ast
import json
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

APP_FILE = Path(__file__).with_name("app_upgraded.py")


def load_validator():
    """Load only validate_message() from the app, without starting the UI."""
    if not APP_FILE.exists():
        raise FileNotFoundError(
            f"Cannot find {APP_FILE.name}. Put this test file beside app_upgraded.py."
        )

    source = APP_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(APP_FILE))
    function_node = next(
        (node for node in tree.body
         if isinstance(node, ast.FunctionDef) and node.name == "validate_message"),
        None,
    )
    if function_node is None:
        raise RuntimeError("Could not find validate_message() in app_upgraded.py")

    module = ast.Module(body=[function_node], type_ignores=[])
    namespace = {
        "json": json,
        "datetime": datetime,
        "timezone": timezone,
        "MAX_AGE_SECONDS": 300,
        "ALLOWED_COMMANDS": {"STATUS", "PING", "RESTART"},
    }
    exec(compile(module, str(APP_FILE), "exec"), namespace)
    return namespace["validate_message"]


validate_message = load_validator()


def valid_message(**changes):
    message = {
        "device_id": "DEVICE-01",
        "command": "STATUS",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sequence": 1,
    }
    message.update(changes)
    return json.dumps(message)


class SentinelXValidationTests(unittest.TestCase):
    def test_valid_message_is_accepted(self):
        accepted, errors, message = validate_message(valid_message())
        self.assertTrue(accepted)
        self.assertEqual(errors, [])
        self.assertEqual(message["command"], "STATUS")

    def test_invalid_json_is_rejected(self):
        accepted, errors, _ = validate_message("{not valid json")
        self.assertFalse(accepted)
        self.assertIn("Invalid JSON format.", errors)

    def test_missing_required_field_is_rejected(self):
        accepted, errors, _ = validate_message('{"device_id":"DEVICE-01"}')
        self.assertFalse(accepted)
        self.assertTrue(any("Missing required field" in error for error in errors))

    def test_unsupported_command_is_rejected(self):
        accepted, errors, _ = validate_message(valid_message(command="DELETE_ALL"))
        self.assertFalse(accepted)
        self.assertIn("Unsupported command.", errors)

    def test_non_positive_sequence_is_rejected(self):
        accepted, errors, _ = validate_message(valid_message(sequence=0))
        self.assertFalse(accepted)
        self.assertIn("sequence must be a positive integer.", errors)

    def test_expired_timestamp_is_rejected(self):
        old_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        accepted, errors, _ = validate_message(valid_message(timestamp=old_time))
        self.assertFalse(accepted)
        self.assertIn("Message timestamp has expired.", errors)

    def test_timestamp_without_timezone_is_rejected(self):
        local_time = datetime.now().replace(microsecond=0).isoformat()
        accepted, errors, _ = validate_message(valid_message(timestamp=local_time))
        self.assertFalse(accepted)
        self.assertIn("Timestamp must include a timezone.", errors)

    def test_non_object_json_is_rejected(self):
        accepted, errors, _ = validate_message('["STATUS"]')
        self.assertFalse(accepted)
        self.assertIn("Message must be a JSON object.", errors)


if __name__ == "__main__":
    unittest.main(verbosity=2)
