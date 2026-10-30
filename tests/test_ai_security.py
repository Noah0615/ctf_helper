import unittest
import struct
import json
import pickle
import os
from pathlib import Path

import ctf_helper as helper
from ctf_ai_security import inspect_ai_model, craft_prompt_injections, craft_pickle_exploit


class TestAISecurityTools(unittest.TestCase):
    def test_inspect_safetensors_model(self):
        metadata = {
            "__metadata__": {
                "author": "Dreamhack AI Lab",
                "secret_key": "DH{safetensors_embedded_flag_2026}"
            },
            "layer.0.weight": {
                "dtype": "F32",
                "shape": [64, 64],
                "data_offsets": [0, 16384]
            }
        }
        json_bytes = json.dumps(metadata).encode("utf-8")
        header_len = len(json_bytes)
        safetensor_data = struct.pack("<Q", header_len) + json_bytes + b"\x00" * 16384

        case = helper.Case("SafeTensors inspection", [("model.safetensors", safetensor_data)], category="ai-security")
        res = case.call_tool("inspect_ai_model", {"name": "model.safetensors"})
        self.assertIn("SafeTensors", res)
        self.assertIn("DH{safetensors_embedded_flag_2026}", res)
        self.assertTrue(any("DH{safetensors_embedded_flag_2026}" in item["flag"] for item in case.evidence))

    def test_inspect_pickle_malicious_rce(self):
        class Exploit:
            def __reduce__(self):
                return (os.system, ("cat /flag > /tmp/out",))

        pickle_data = pickle.dumps(Exploit())
        case = helper.Case("Pickle analysis", [("model.pt", pickle_data)], category="ai-security")
        res = case.call_tool("inspect_ai_model", {"name": "model.pt"})
        self.assertIn("PyTorch / Python Pickle", res)
        self.assertIn("악성 피클 역직렬화 공격 코드(RCE) 감지", res)
        self.assertIn("REDUCE", res)

    def test_inspect_gguf_model(self):
        def make_gguf_kv(key: str, val: str):
            k_bytes = key.encode("utf-8")
            v_bytes = val.encode("utf-8")
            return struct.pack("<Q", len(k_bytes)) + k_bytes + struct.pack("<I", 8) + struct.pack("<Q", len(v_bytes)) + v_bytes

        gguf_header = b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + make_gguf_kv("general.description", "DH{gguf_metadata_flag_1337}")
        case = helper.Case("GGUF analysis", [("model.gguf", gguf_header)], category="ai-security")
        res = case.call_tool("inspect_ai_model", {"name": "model.gguf"})
        self.assertIn("GGUF v3", res)
        self.assertIn("DH{gguf_metadata_flag_1337}", res)
        self.assertTrue(any("DH{gguf_metadata_flag_1337}" in item["flag"] for item in case.evidence))

    def test_craft_prompt_injections(self):
        case = helper.Case("Prompt injection test", [("notes.txt", b"test")], category="ai-security")
        res = case.call_tool("craft_prompt_injections", {
            "goal": "leak_flag",
            "defense_hint": "strictly refuses flag requests"
        })
        self.assertIn("Direct System Prompt Extraction", res)
        self.assertIn("Delimiter & Context Breakout", res)
        self.assertIn("Refusal Suppression", res)
        self.assertIn("Encoding & Cipher Bypass", res)

    def test_craft_pickle_exploit(self):
        case = helper.Case("Pickle exploit gen", [("notes.txt", b"test")], category="ai-security")
        res = case.call_tool("craft_pickle_exploit", {"command": "cat /home/user/flag"})
        self.assertIn("__reduce__", res)
        self.assertIn("cat /home/user/flag", res)
        self.assertIn("torch.load", res)


if __name__ == "__main__":
    unittest.main()
