"""Tests for TCP one-shot handling, Python error diagnosis, and loop prevention."""
import unittest
from unittest.mock import patch, MagicMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import ctf_helper as helper


class TcpAndRepetitionTests(unittest.TestCase):

    def test_tcp_exchange_strips_leading_empty_string(self):
        """When model passes ['', 'cmd'], the leading empty string is stripped so one-shot services aren't killed."""
        case = helper.Case("Python challenge", [("app.py", b"exec(input('> '))")],
                           tcp_endpoint="ctf.example:9999", flag_regex="DH{...}")
        conn = MagicMock()
        conn.__enter__.return_value.recv.side_effect = [b"> ", helper.socket.timeout, b"DH{success}\n", helper.socket.timeout]
        with patch.object(helper.socket, "create_connection", return_value=conn):
            output = case.tcp_exchange(["", "print(open('flag').read())"])

        # Should send the command, NOT the empty newline first
        conn.__enter__.return_value.sendall.assert_called_once_with(b"print(open('flag').read())\n")
        self.assertIn("DH{success}", output)

    def test_tcp_exchange_diagnoses_python_interpreter_errors(self):
        """When TCP server returns a Python NameError, diagnostic guidance is appended."""
        case = helper.Case("Python challenge", [], tcp_endpoint="ctf.example:9999", flag_regex="DH{...}")
        conn = MagicMock()
        conn.__enter__.return_value.recv.side_effect = [
            b"> ", helper.socket.timeout,
            b"NameError: name 'GET' is not defined\n", helper.socket.timeout
        ]
        with patch.object(helper.socket, "create_connection", return_value=conn):
            output = case.tcp_exchange(["GET / HTTP/1.1"])

        self.assertIn("NameError: name 'GET' is not defined", output)
        self.assertIn("CTF 도우미 진단", output)
        self.assertIn("Python exec()", output)
        self.assertIn("print(open('flag').read())", output)

    def test_call_tool_blocks_identical_repetition(self):
        """When identical network request is repeated, it is blocked to preserve the 8-request limit."""
        case = helper.Case("Python challenge", [], tcp_endpoint="ctf.example:9999", flag_regex="DH{...}")
        conn = MagicMock()
        conn.__enter__.return_value.recv.side_effect = [
            b"> ", helper.socket.timeout,
            b"NameError: name 'GET' is not defined\n", helper.socket.timeout
        ]
        with patch.object(helper.socket, "create_connection", return_value=conn):
            res1 = case.call_tool("tcp_exchange", {"steps": ["GET / HTTP/1.1"]})
        self.assertEqual(case.tcp_requests, 1)

        # Call identically again
        res2 = case.call_tool("tcp_exchange", {"steps": ["GET / HTTP/1.1"]})
        self.assertIn("반복 호출 차단", res2)
        # tcp_requests count must NOT have increased!
        self.assertEqual(case.tcp_requests, 1)


if __name__ == "__main__":
    unittest.main()
