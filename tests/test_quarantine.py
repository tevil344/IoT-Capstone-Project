"""Unit tests for QuarantineManager."""

import os
import tempfile
import unittest

from gateway.quarantine.manager import QuarantineManager, normalize_mac


class TestQuarantineManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_gateway.db")
        self.manager = QuarantineManager(db_path=self.db_path, dry_run=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_normalize_mac(self):
        self.assertEqual(normalize_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("aa-bb-cc-dd-ee-ff"), "aa:bb:cc:dd:ee:ff")
        with self.assertRaises(ValueError):
            normalize_mac("invalid-mac-address")

    def test_quarantine_lifecycle(self):
        mac = "00:11:22:33:44:55"
        self.assertFalse(self.manager.is_quarantined(mac))

        # Quarantine device
        res = self.manager.quarantine_mac(mac, reason="new_iot_device")
        self.assertTrue(res)
        self.assertTrue(self.manager.is_quarantined(mac))
        self.assertIn(mac, self.manager.list_quarantined_macs())

        # Release to trusted
        res_rel = self.manager.release_mac(mac, reason="fingerprint_verified")
        self.assertTrue(res_rel)
        self.assertFalse(self.manager.is_quarantined(mac))
        self.assertNotIn(mac, self.manager.list_quarantined_macs())

        # Check audit trail
        history = self.manager.get_audit_history(mac)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["action"], "QUARANTINE")
        self.assertEqual(history[0]["reason"], "new_iot_device")
        self.assertEqual(history[1]["action"], "RELEASE_TO_TRUSTED")
        self.assertEqual(history[1]["reason"], "fingerprint_verified")


if __name__ == "__main__":
    unittest.main()

