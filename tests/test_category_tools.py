import unittest
import sys
from pathlib import Path
import tempfile
import io

import ctf_helper as helper
from ctf_category_tools import extract_crypto_params, carve_file_signatures, inspect_pcap, diff_http_responses
from ctf_binary_tools import calculate_stack_layout, find_rop_gadgets, find_string_xrefs


class TestCategoryTools(unittest.TestCase):
    def test_extract_crypto_params_byte_caesar(self):
        # Synthetic Byte-Caesar with key=178
        flag = b"DH{caesar_byte_shift_success}"
        enc = bytes((b + 178) % 256 for b in flag)
        res = extract_crypto_params(f"encrypted data: {enc.hex()}")
        self.assertIn("Byte-Caesar", res)
        self.assertIn("DH{caesar_byte_shift_success}", res)
        self.assertIn("178", res)

    def test_extract_crypto_params_xor(self):
        # Synthetic single-byte XOR
        flag = b"DH{single_byte_xor_success}"
        enc = bytes(b ^ 0x5a for b in flag)
        res = extract_crypto_params(f"xor data: {enc.hex()}")
        self.assertIn("Single-byte XOR", res)
        self.assertIn("DH{single_byte_xor_success}", res)
        self.assertIn("0x5a", res)

    def test_decode_text_byte_shift(self):
        flag = b"DH{decode_text_byte_shift_test}"
        enc = bytes((b + 42) % 256 for b in flag)
        case = helper.Case("Byte-shift test", [("dummy.txt", b"test")])
        res = case.decode_text(enc.hex())
        self.assertIn("byte_shift_0x2a", res)
        self.assertIn("DH{decode_text_byte_shift_test}", res)

    def test_extract_crypto_params_e3(self):
        text = '''
        n = 0x93821039481239081239
        e = 3
        c = 0x827361
        '''
        res = extract_crypto_params(text)
        self.assertIn('n =', res)
        self.assertIn('e = 3', res)
        self.assertIn('cube root', res.lower())

    def test_extract_crypto_params_known_pq(self):
        text = '''
        p = 61
        q = 53
        e = 17
        c = 2790
        '''
        res = extract_crypto_params(text)
        self.assertIn('p = 61', res)
        self.assertIn('d = pow(e, -1, (p-1)*(q-1))', res)

    def test_extract_crypto_params_via_case(self):
        case = helper.Case('Crypto analysis', [('params.txt', b'n = 1234567\ne = 3\nc = 999\n')])
        res_file = case.call_tool('extract_crypto_params', {'file_name': 'params.txt'})
        self.assertIn('n = 1234567', res_file)
        self.assertIn('e = 3', res_file)

        res_direct = case.call_tool('extract_crypto_params', {'text': 'p = 101\nq = 103\ne = 65537\nc = 555\n'})
        self.assertIn('p = 101', res_direct)

    def test_carve_file_signatures(self):
        # Create a synthetic PNG with overlay data
        png_data = b'\x89PNG\r\n\x1a\n' + b'\x00'*16 + b'IEND\xaeB\x60\x82' + b'HIDDEN_STEGO_PAYLOAD'
        case = helper.Case('Forensics carve', [('image.png', png_data)])
        res = case.call_tool('carve_file_signatures', {'name': 'image.png'})
        self.assertIn('PNG Image', res)
        self.assertIn('Steganography', res)

    def test_inspect_pcap(self):
        # Synthetic PCAP with HTTP GET and a flag
        pcap_header = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00'
        pcap_payload = b'GET /flag HTTP/1.1\r\nHost: dreamhack.games\r\n\r\nDH{sniffed_in_packet_payload_1337}'
        pcap_bytes = pcap_header + pcap_payload

        case = helper.Case('Network forensics', [('capture.pcap', pcap_bytes)])
        res = case.call_tool('inspect_pcap', {'name': 'capture.pcap'})
        self.assertIn('DH{sniffed_in_packet_payload_1337}', res)
        self.assertIn('GET /flag', res)
        # Check automatic flag capture in evidence
        self.assertTrue(any('DH{sniffed_in_packet_payload_1337}' in item['flag'] for item in case.evidence))

    def test_diff_http_responses(self):
        body1 = 'Welcome user! Access Granted.'
        body2 = 'Welcome user! Access Denied.'
        diff = diff_http_responses(body1, body2, 'Admin', 'Guest')
        self.assertIn('Diff', diff)
        self.assertIn('+Welcome user! Access Denied.', diff)
        self.assertIn('-Welcome user! Access Granted.', diff)

        # Identical responses
        same = diff_http_responses(body1, body1, 'Req1', 'Req2')
        self.assertIn('Req1', same)

    def test_diff_http_responses_via_case(self):
        case = helper.Case('Web blind sql diff', [('dummy.txt', b'dummy')])
        res = case.call_tool('diff_http_responses', {
            'body1': 'Login success: flag length is 10',
            'body2': 'Login failure: flag length is not 10'
        })
        self.assertIn('Diff', res)

    def test_binary_tools_integration_on_elf(self):
        chall_path = Path('results/ctf_helper/20261029_165710_23319e8c/files/chall')
        if not chall_path.exists():
            chall_path = Path('../results/ctf_helper/20261029_165710_23319e8c/files/chall')
        if not chall_path.exists():
            self.skipTest('Sample ELF chall not found on disk')

        case = helper.Case('Pwn challenge', [('chall', chall_path.read_bytes())])
        
        # 1. find_rop_gadgets
        rop_res = case.call_tool('find_rop_gadgets', {'name': 'chall', 'max_gadgets': 10})
        self.assertIn('ret', rop_res)

        # 2. calculate_stack_layout
        layout_res = case.call_tool('calculate_stack_layout', {'name': 'chall', 'symbol': 'main'})
        self.assertIn('main', layout_res)

        # 3. find_string_xrefs
        xref_res = case.call_tool('find_string_xrefs', {'name': 'chall', 'term': 'puts'})
        self.assertIn('puts', xref_res)



    def test_extract_crypto_params_lfsr_stream(self):
        flag = b'DH{synthetic_lfsr_stream_test_32}'
        size = 32
        taps = (32, 22, 2, 1)
        seed = 0x12345678
        state = bin(seed)[2:].zfill(size)
        def shift():
            nonlocal state
            nb = 0
            for t in taps:
                nb ^= int(state[t - 1])
            state = str(nb) + state[:-1]
            return str(nb)

        ct = bytes([b ^ int(''.join(shift() for _ in range(8)), 2) for b in flag])
        text = f'taps = (32, 22, 2, 1)\nencrypted = {ct.hex()}'
        res = extract_crypto_params(text)
        self.assertIn('LFSR 스트림 암호', res)
        self.assertIn(flag.decode(), res)

    def test_extract_crypto_params_lfsr_fibonacci(self):
        flag = b'FLAG{fibonacci_lfsr_synthetic_123}'
        size = 32
        taps = (32, 22, 2, 1)
        seed = 0xa5b4c3d2
        state = list(bin(seed)[2:].zfill(size))
        def clock():
            nonlocal state
            nb = 0
            for t in taps:
                nb ^= int(state[t - 1])
            state = [str(nb)] + state[:-1]
            return int(state[-1])

        ct = bytes([b ^ int(''.join(str(clock()) for _ in range(8)), 2) for b in flag])
        text = f'taps = (32, 22, 2, 1)\noutput = {ct.hex()}'
        res = extract_crypto_params(text)
        self.assertIn('LFSR', res)
        self.assertIn(flag.decode(), res)

    def test_extract_crypto_params_lfsr_via_case_files_dir(self):
        flag = b'DH{case_files_dir_lfsr_solved_ok}'
        size = 32
        taps = (32, 22, 2, 1)
        seed = 0xabcdef12
        state = bin(seed)[2:].zfill(size)
        def shift():
            nonlocal state
            nb = 0
            for t in taps:
                nb ^= int(state[t - 1])
            state = str(nb) + state[:-1]
            return str(nb)

        ct = bytes([b ^ int(''.join(shift() for _ in range(8)), 2) for b in flag])
        case = helper.Case('LFSR test', [
            ('cipher.py', b'class STREAM:\n    def __init__(self):\n        self.taps = (32, 22, 2, 1)\n'),
            ('output.txt', f'encrypted flag > {ct.hex()}\n'.encode())
        ])
        res = case.call_tool('extract_crypto_params', {})
        self.assertIn(flag.decode(), res)
        self.assertTrue(any(flag.decode() in item['flag'] for item in case.evidence))

    def test_run_python_crypto_shim(self):
        case = helper.Case('Crypto run_python test', [], docker_python=True)
        res = case.run_python('from Crypto.Util.number import long_to_bytes\nprint(long_to_bytes(0x44487b746573747d).decode())')
        if '격리 이미지가 없습니다' in res or 'Docker 명령을 찾을 수 없습니다' in res:
            self.skipTest('Docker unavailable or image missing')
        self.assertIn('exit=0', res)
        self.assertIn('DH{test}', res)



    def test_predict_mongodb_objectids(self):
        from ctf_category_tools import predict_mongodb_objectids, analyze_mongodb_objectids
        sample_json = """
        [
          {"_id":"6ae44f712c947927537cc280","title":"Hello","author":"guest","secret":false,"publish_date":"2026-10-30T08:04:01.982Z"},
          {"_id":"6ae44f752c947927537cc281","title":"Mongo","author":"guest","secret":false,"publish_date":"2026-10-30T08:04:05.991Z"},
          {"_id":null,"title":"FLAG","author":"admin","secret":true,"publish_date":"2026-10-30T08:04:08.992Z"},
          {"_id":"6ae44f7d2c947927537cc283","title":"Good","author":"guest","secret":false,"publish_date":"2026-10-30T08:04:13.993Z"}
        ]
        """
        preds = predict_mongodb_objectids(sample_json)
        self.assertEqual(preds[0], "6ae44f782c947927537cc282")
        diag = analyze_mongodb_objectids(sample_json, "/api/board/<OID>")
        self.assertIn("6ae44f782c947927537cc282", diag)
        self.assertIn("MongoDB < 4.0.0", diag)

    def test_predict_objectid_via_case(self):
        sample_json = """
        [
          {"_id":"6ae44f752c947927537cc281","title":"Mongo","author":"guest","secret":false,"publish_date":"2026-10-30T08:04:05.991Z"},
          {"_id":null,"title":"FLAG","author":"admin","secret":true,"publish_date":"2026-10-30T08:04:08.992Z"},
          {"_id":"6ae44f7d2c947927537cc283","title":"Good","author":"guest","secret":false,"publish_date":"2026-10-30T08:04:13.993Z"}
        ]
        """
        case = helper.Case("Objectid test", [])
        res = case.call_tool("predict_objectid", {"data": sample_json, "endpoint_template": "/api/board/:board_id"})
        self.assertIn("6ae44f782c947927537cc282", res)

    def test_http_get_mongodb_objectid_auto_detection(self):
        import http.server
        import threading
        import json

        sample_board = json.dumps([
            {"_id":"6ae44f752c947927537cc281","title":"Mongo","author":"guest","secret":False,"publish_date":"2026-10-30T08:04:05.991Z"},
            {"_id":None,"title":"FLAG","author":"admin","secret":True,"publish_date":"2026-10-30T08:04:08.992Z"},
            {"_id":"6ae44f7d2c947927537cc283","title":"Good","author":"guest","secret":False,"publish_date":"2026-10-30T08:04:13.993Z"}
        ])

        class MockHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/api/board":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(sample_board.encode())
                elif self.path == "/api/board/6ae44f782c947927537cc282":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    doc = {"_id": "6ae44f782c947927537cc282", "title": "FLAG", "body": "DH{test_mongo_auto_probed_flag}"}
                    self.wfile.write(json.dumps(doc).encode())
                else:
                    self.send_response(404)
                    self.end_headers()
            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), MockHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            case = helper.Case("Mongo auto-probe test", [], tcp_endpoint=f"http://127.0.0.1:{port}/")
            res = case.call_tool("http_get", {"path": "/api/board"})
            self.assertIn("6ae44f782c947927537cc282", res)
            self.assertIn("DH{test_mongo_auto_probed_flag}", res)
            self.assertTrue(any("DH{test_mongo_auto_probed_flag}" in item["flag"] for item in case.evidence))
        finally:
            server.shutdown()


if __name__ == '__main__':
    unittest.main()
