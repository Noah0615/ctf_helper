import unittest
import sys
from pathlib import Path
import tempfile
import io

import ctf_helper as helper
from ctf_category_tools import extract_crypto_params, carve_file_signatures, inspect_pcap, diff_http_responses
from ctf_binary_tools import calculate_stack_layout, find_rop_gadgets, find_string_xrefs


class TestCategoryTools(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
