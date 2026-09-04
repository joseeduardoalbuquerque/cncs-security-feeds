import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "manage_feed.py"
SPEC = importlib.util.spec_from_file_location("manage_feed", MODULE_PATH)
manage_feed = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(manage_feed)


class ManageFeedTests(unittest.TestCase):
    def test_normalises_and_deduplicates(self):
        result = manage_feed.parse_indicators("8.8.8.8\n8.8.8.8/32, 2606:4700:4700::1111")
        self.assertEqual([item[0] for item in result], ["8.8.8.8", "2606:4700:4700::1111"])

    def test_rejects_non_global_by_default(self):
        with self.assertRaises(manage_feed.FeedError):
            manage_feed.parse_indicators("192.0.2.10")

    def test_accepts_non_global_when_explicit(self):
        result = manage_feed.parse_indicators("192.0.2.10", allow_non_global=True)
        self.assertEqual(result[0][0], "192.0.2.10")

    def test_add_remove_and_validate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "data.json"
            feed = root / "feed.txt"
            items = manage_feed.parse_indicators("8.8.8.8\n1.1.1.0/24")

            added = manage_feed.apply_operation(
                "add", items, database, feed, "CNCS test", "2026-09-04T10:00:00Z"
            )
            self.assertEqual(added["added"], 2)
            self.assertEqual(feed.read_text(), "1.1.1.0/24\n8.8.8.8\n")

            removed = manage_feed.apply_operation(
                "remove", [items[0]], database, feed, "CNCS withdrawal", "2026-09-04T11:00:00Z"
            )
            self.assertEqual(removed["removed"], 1)
            self.assertEqual(feed.read_text(), "1.1.1.0/24\n")
            self.assertEqual(manage_feed.validate_repository(database, feed)["active"], 1)

            stored = json.loads(database.read_text())
            self.assertEqual(stored["indicators"]["8.8.8.8"]["status"], "inactive")

    def test_feed_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "data.json"
            feed = root / "feed.txt"
            manage_feed.save_database(database, manage_feed.empty_database())
            feed.write_text("8.8.8.8\n")
            with self.assertRaises(manage_feed.FeedError):
                manage_feed.validate_repository(database, feed)

    def test_repository_dispatch_event(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "data.json"
            feed = root / "feed.txt"
            event_path = root / "event.json"
            event_path.write_text(json.dumps({
                "client_payload": {
                    "operation": "add",
                    "indicators": ["8.8.4.4", "2606:4700:4700::1111"],
                    "source_ref": "CNCS automated test",
                    "observed_at": "2026-09-04T12:00:00Z"
                }
            }))
            args = type("Args", (), {
                "event_json": event_path,
                "database": database,
                "feed": feed,
                "inbox": root / "inbox.txt",
            })()
            result = manage_feed.process_event(args)
            self.assertEqual(result["added"], 2)
            self.assertEqual(feed.read_text(), "8.8.4.4\n2606:4700:4700::1111\n")


if __name__ == "__main__":
    unittest.main()
