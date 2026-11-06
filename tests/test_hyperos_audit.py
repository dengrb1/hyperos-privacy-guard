import unittest
from pathlib import Path

from hyperos_audit import AdbClient, decode_ipv6, parse_appops, parse_proc_tcp, parse_proc_tcp6


class AuditParserTest(unittest.TestCase):
    def test_appops_keeps_package_scoped_modes(self):
        output = """
        Package com.example.reader:
          GET_USAGE_STATS: ignore; time=+1m
          android:camera: allow
        Package com.example.other:
          GET_USAGE_STATS: default
        """
        parsed = parse_appops(output)
        self.assertEqual(parsed["com.example.reader"][0]["mode"], "ignore")
        self.assertEqual(parsed["com.example.other"][0]["operation"], "GET_USAGE_STATS")

    def test_proc_tcp_uses_uid_field_and_decodes_ipv4(self):
        output = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0200000A:01BB 01 00000000:0000 00:00000000 00000000 12345        0 123 1 0000000000000000 100 0 0 10 0
        """
        rows = parse_proc_tcp(output)
        self.assertEqual(rows[0]["remote_ip"], "10.0.0.2")
        self.assertEqual(rows[0]["remote_port"], 443)
        self.assertEqual(rows[0]["uid"], "12345")

    def test_proc_tcp6_decodes_words_in_kernel_order(self):
        output = """  sl  local_address                         rem_address                         st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000001000000:01BB 01 0:0 0:0 0 10042 0 123
        """
        rows = parse_proc_tcp6(output)
        self.assertEqual(rows[0]["remote_ip"], "::1")
        self.assertEqual(rows[0]["remote_port"], 443)
        self.assertEqual(rows[0]["uid"], "10042")
        self.assertEqual(decode_ipv6("00000000000000000000000001000000"), "::1")

    def test_shell_rejects_unreviewed_or_mutating_commands(self):
        client = AdbClient(Path("adb.exe"), None, 5, Path("."))
        with self.assertRaises(ValueError):
            client.shell("pm grant com.example android.permission.READ_CONTACTS", name="bad")
        with self.assertRaises(ValueError):
            client.shell("pm list packages -f", name="not-in-allow-list")


if __name__ == "__main__":
    unittest.main()
