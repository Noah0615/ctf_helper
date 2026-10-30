"""Focused offline checks for the local CTF assistant."""
from types import SimpleNamespace
import base64
import io
import json
from pathlib import Path
from urllib.parse import parse_qs
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ctf_helper as helper
import ctf_openai as openai_helper


class HelperTests(unittest.TestCase):
    def setUp(self):
        (helper.ROOT / ".runtime").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=helper.ROOT / ".runtime")
        self.addCleanup(self.temp.cleanup)
        self.patch_results = patch.object(helper, "RESULTS", Path(self.temp.name))
        self.patch_results.start()
        self.addCleanup(self.patch_results.stop)

    def test_local_dpapi_key_detection_and_loading(self):
        key_file = Path(self.temp.name) / "dummy-key.dpapi"
        key_script = Path(self.temp.name) / "dummy-reader.ps1"
        with patch.object(openai_helper, "KEY_FILE", key_file), patch.object(openai_helper, "KEY_SCRIPT", key_script):
            self.assertFalse(openai_helper.key_present())
            key_file.write_bytes(b"dummy")
            key_script.write_text("# dummy", encoding="utf-8")
            self.assertTrue(openai_helper.key_present())
            with patch.object(openai_helper.shutil, "which", return_value="powershell.exe"), \
                 patch.object(openai_helper.subprocess, "run", return_value=SimpleNamespace(
                     returncode=0, stdout="sk-test-only", stderr="")):
                self.assertEqual(openai_helper.load_key(), "sk-test-only")

    def test_rejects_paths_and_duplicate_names_before_creation(self):
        with self.assertRaises(ValueError):
            helper.Case("example", [("../secret.txt", b"x")])
        with self.assertRaises(ValueError):
            helper.Case("example", [("A.py", b"x"), ("a.PY", b"y")])
        with self.assertRaises(ValueError):
            helper.Case("example", [("CON.txt", b"x")])
        with self.assertRaises(ValueError):
            helper.Case("example", [("folder/../secret.txt", b"x")])
        with self.assertRaises(ValueError):
            helper.Case("example", [("folder", b"x"), ("folder/child.txt", b"y")])
        with self.assertRaisesRegex(ValueError, "256개"):
            helper.Case("example", [(f"file-{n}.txt", b"") for n in range(257)])
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_accepts_common_libc_size_within_total_upload_limit(self):
        case = helper.Case("Inspect libc", [("libc-2.39.so", b"\0" * (9 * 1024 * 1024))])
        self.assertEqual((case.files_dir / "libc-2.39.so").stat().st_size, 9 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, "32 MiB"):
            helper.Case("Too large", [("large.bin", b"\0" * (33 * 1024 * 1024))])

    def test_nested_folder_files_are_visible_to_all_file_tools(self):
        case = helper.Case("Inspect folder", [
            ("challenge/src/app.py", b"SECRET = 'nested-value'\n"),
            ("challenge/templates/index.html", b"<h1>hello</h1>"),
        ])
        listed = json.loads(case.list_files())
        self.assertEqual([item["name"] for item in listed],
                         ["challenge/src/app.py", "challenge/templates/index.html"])
        self.assertIn("nested-value", case.read_file("challenge/src/app.py"))
        self.assertIn("challenge/src/app.py:1", case.search_files("nested-value"))
        with self.assertRaises(ValueError):
            case.read_file("challenge/../../problem.txt")
        case.finish(helper.DEFAULT_MODEL, "계속 분석", [])
        resumed = helper.Case.from_run(case.id, "새 단서")
        self.assertIn("nested-value", resumed.read_file("challenge/src/app.py"))

    def test_reads_files_decodes_and_records_provenance(self):
        case = helper.Case("Decode the encoded text", [("cipher.txt", b"QUNEQ3t0ZXN0X2ZsYWd9")])
        self.assertIn("cipher.txt:1", case.search_files("QUN"))
        self.assertIn("ACDC{test_flag}", case.decode_text("QUNEQ3t0ZXN0X2ZsYWd9"))
        self.assertEqual(case.evidence[0]["source"], "디코딩 결과")
        self.assertIn("디코딩으로 도출됨", case.evidence[0]["status"])
        with self.assertRaises(ValueError):
            case.read_file("../problem.txt")
        extensionless = helper.Case("Review the code", [("Dockerfile", b"FROM scratch\n")])
        self.assertIn("FROM scratch", extensionless.read_file("Dockerfile"))

    def test_agent_tool_cycle_produces_saved_candidate(self):
        case = helper.Case("Decode the attachment", [("cipher.txt", b"QUNEQ3t0ZXN0X2ZsYWd9")])
        responses = iter([
            {"message": {"role": "assistant", "content": "", "tool_calls": [{"type": "function", "function": {
                "name": "decode_text", "arguments": {"text": "QUNEQ3t0ZXN0X2ZsYWd9"}}}]}},
            {"message": {"role": "assistant", "content": "디코딩 결과: ACDC{test_flag}"}}
        ])
        def fake_request(path, payload=None, timeout=30):
            if path == "/api/tags":
                return {"models": [{"name": helper.DEFAULT_MODEL}]}
            return next(responses)
        with patch.object(helper, "ollama_request", side_effect=fake_request):
            result = case.solve(max_steps=3)
        self.assertEqual(result["flag_candidates"][0]["flag"], "ACDC{test_flag}")
        self.assertFalse(result["officially_verified"])
        self.assertTrue((case.root / "result.json").exists())
        self.assertEqual(len(result["steps"]), 3)

    def test_python_requires_opt_in_and_uses_offline_container(self):
        case = helper.Case("calculate", [], docker_python=False)
        self.assertIn("비활성화", case.run_python("print(2)"))
        case.docker_python = True
        class Done:
            stdout = "ACDC{calculated}"
            stderr = ""
            returncode = 0
        with patch.object(helper.shutil, "which", return_value="docker"), \
             patch.object(helper.subprocess, "run", return_value=Done()) as run:
            output = case.run_python("print('ACDC{calculated}')")
        command = run.call_args.args[0]
        self.assertIn("--network=none", command)
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("ACDC{calculated}", output)
        self.assertEqual(case.evidence[0]["source"], "격리 Python 실행 출력")

    def test_placeholder_is_not_a_flag_and_remote_absence_is_explicit(self):
        pattern = helper.get_flag_pattern(helper.DEFAULT_FLAG_REGEX)
        self.assertEqual(helper.extract_flags("형식 DH{...}; 기본값 APS{REDACTED}; 실제 DH{real_value}", pattern),
                         ["DH{real_value}"])
        self.assertEqual(helper.extract_flags("DH{**Fake_Flag**} DH{dummy_flag} DH{real_value}", pattern),
                         ["DH{real_value}"])
        case = helper.Case("형식은 DH{...}", [("welcome.c", b'fp = fopen("/flag", "r");')])
        self.assertEqual(case.evidence, [])
        result = case.finish(helper.DEFAULT_MODEL, "DH{...}는 형식입니다.", [])
        self.assertEqual(result["flag_candidates"], [])
        self.assertIn("정확한 flag를 확인하지 못했습니다", result["answer"])

    def test_display_flag_format_is_accepted_in_regex_field(self):
        pattern = helper.get_flag_pattern("DH{...}")
        self.assertEqual(helper.extract_flags("형식 DH{...}; 실제 DH{robots_txt_is_not_security}", pattern),
                         ["DH{robots_txt_is_not_security}"])

    def test_challenge_format_mismatch_stops_before_paid_analysis(self):
        description = "플래그의 형식은 DH{...} 입니다."
        files = [("app.py", b'FLAG = "APS{REDACTED}"'),
                 ("README.md", b'Flag format: APS{...}')]
        with self.assertRaisesRegex(ValueError, "서로 다른 문제"):
            helper.Case(description, files)
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])
        case = helper.Case(description, files, allow_mismatch=True)
        self.assertEqual(case.category, "auto")

    def test_css_and_js_braces_do_not_trigger_flag_format_mismatch(self):
        files = [
            ("challenge/deploy/app.py", b'FLAG = os.environ.get("FLAG")\n'),
            ("challenge/deploy/static/css/bootstrap.css",
             b'.container{width:100%}.navbar{display:block}.FLAG{color:red}.warning{padding:0}'),
            ("challenge/deploy/static/js/bootstrap.js", b'function toggle(){return true;}'),
            ("challenge/notes.txt", b'OTHER{not_a_declared_flag_format}'),
        ]
        case = helper.Case("플래그 형식은 DH{...} 입니다.", files)
        self.assertIn("challenge/deploy/app.py", case.list_files())

    def test_tcp_banner_flag_is_observed_but_does_not_skip_analysis(self):
        case = helper.Case("형식 DH{...}", [], tcp_endpoint="ctf.example:1234")
        conn = MagicMock()
        conn.__enter__.return_value.recv.side_effect = [b"FLAG : DH{from_service}\n", b""]
        with patch.object(helper.socket, "create_connection", return_value=conn) as connect, \
             patch.object(helper, "ollama_request", side_effect=[
                 {"models": [{"name": helper.DEFAULT_MODEL}]},
                 {"message": {"content": "배너의 값은 후보이며 공식 채점은 미확인입니다."}}
             ]) as model_call:
            result = case.solve(max_steps=1)
        connect.assert_called_once_with(("ctf.example", 1234), timeout=5)
        self.assertEqual(model_call.call_count, 2)
        self.assertEqual([item["flag"] for item in result["flag_candidates"]], ["DH{from_service}"])
        self.assertEqual(len(result["steps"]), 1)
        self.assertIn("문제 서버 출력", result["flag_candidates"][0]["status"])
        self.assertEqual(result["result_status"], "remote_observed")
        self.assertEqual(result["remote_observed_flags"], ["DH{from_service}"])

    def test_tcp_exchange_reads_menu_and_excludes_fake_input_flag(self):
        case = helper.Case("Pwn challenge", [("flag", b"DH{**Fake_Flag**}")],
                           tcp_endpoint="ctf.example:1234", flag_regex="DH{...}")
        self.assertEqual(case.evidence, [])
        conn = MagicMock()
        conn.__enter__.return_value.recv.side_effect = [b"1. Create user\n> ", helper.socket.timeout,
                                                       b"DH{remote_real}\n", helper.socket.timeout]
        with patch.object(helper.socket, "create_connection", return_value=conn) as connect:
            output = case.tcp_exchange(["1"])
        connect.assert_called_once_with(("ctf.example", 1234), timeout=5)
        conn.__enter__.return_value.sendall.assert_called_once_with(b"1\n")
        self.assertIn("DH{remote_real}", output)
        self.assertEqual(case.evidence[0]["source"], "문제 서버: ctf.example:1234")
        self.assertEqual(case.tcp_requests, 1)

    def test_local_model_continues_after_fake_flag(self):
        case = helper.Case("Pwn challenge", [("flag", b"DH{**Fake_Flag**}")], flag_regex="DH{...}")
        responses = iter([
            {"message": {"content": "DH{**Fake_Flag**} is present; maybe stop."}},
            {"message": {"content": "", "tool_calls": [{"function": {"name": "list_files", "arguments": {}}}]}},
            {"message": {"content": "정확한 원격 플래그는 아직 확인하지 못했습니다."}}
        ])
        def fake_request(path, payload=None, timeout=30):
            return {"models": [{"name": helper.DEFAULT_MODEL}]} if path == "/api/tags" else next(responses)
        with patch.object(helper, "ollama_request", side_effect=fake_request):
            result = case.solve(max_steps=3)
        self.assertEqual(len([step for step in result["steps"] if "turn" in step]), 3)
        self.assertEqual(result["flag_candidates"], [])

    def test_explicit_web_origin_limits_model_requests_to_that_origin(self):
        case = helper.Case("웹 문제", [], tcp_endpoint="http://ctf.example:8000/")
        fake_response = MagicMock()
        fake_response.status = 200
        fake_response.read.return_value = b"marker=APS{from_web}"
        with patch.object(helper, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value = fake_response
            output = case.http_get("/audit?q=test", {"X-API-Key": "challenge-token"})
        self.assertIn("APS{from_web}", output)
        self.assertEqual(case.evidence[0]["flag"], "APS{from_web}")
        self.assertIn("문제 웹 응답", case.evidence[0]["source"])
        self.assertIn("직접 확인", case.evidence[0]["status"])
        self.assertEqual(case.requests[0]["method"], "GET")
        self.assertEqual(case.requests[0]["path"], "/audit?q=test")
        self.assertEqual(case.requests[0]["headers"]["X-API-Key"], "<redacted>")
        self.assertTrue((case.root / "requests.jsonl").is_file())
        self.assertIn("상대 경로", case.http_get("https://elsewhere.example/"))
        with self.assertRaises(ValueError):
            helper.Case("웹 문제", [], tcp_endpoint="http://ctf.example:8000/path")

    def test_bounded_web_oracles_complete_prefix_and_integer_search(self):
        case = helper.Case("Find the locker", [], flag_regex="DH{...}",
                           tcp_endpoint="http://ctf.example:8000/")
        case.http_direct_requests = helper.MAX_DIRECT_HTTP_REQUESTS

        class Reply:
            status = 200
            headers = {"Content-Type": "text/html"}
            def __init__(self, body):
                self.body = body.encode()
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def read(self, *_):
                return self.body

        def fake_open(request, timeout):
            self.assertEqual(request.full_url, "http://ctf.example:8000/")
            form = parse_qs(request.data.decode())
            candidate = form["locker_num"][0]
            password = form["password"][0]
            if candidate == "b2" and password == "102":
                return Reply("<pre>FLAG:DH{oracle_test}</pre>")
            return Reply("<pre>Good</pre>" if "b2".startswith(candidate) else "<pre>Wrong!</pre>")

        with patch.object(helper, "build_opener") as opener:
            opener.return_value.open.side_effect = fake_open
            prefix = json.loads(case.call_tool("http_prefix_oracle", {
                "path": "/", "field": "locker_num", "alphabet": "ab12", "length": 2,
                "success_marker": "<pre>Good</pre>", "fixed_fields": {"password": "0"}}))
            self.assertEqual(prefix["prefix"], "b2")
            found = json.loads(case.call_tool("http_integer_oracle", {
                "path": "/", "field": "password", "start": 100, "stop": 103,
                "success_marker": "FLAG:", "fixed_fields": {"locker_num": prefix["prefix"]}}))
        self.assertEqual(found["flags"], ["DH{oracle_test}"])
        self.assertEqual(case.http_direct_requests, helper.MAX_DIRECT_HTTP_REQUESTS)
        self.assertGreater(case.http_batch_requests, 8)
        self.assertEqual(len(case.requests), case.http_batch_requests)
        self.assertIn("최대 8회", case.http_post("/", "x=1"))
        self.assertIn("300", case.call_tool("http_integer_oracle", {
            "path": "/", "field": "password", "start": 0, "stop": 300,
            "success_marker": "FLAG:"}))

    def test_batch_web_tools_are_hidden_without_a_supplied_web_origin(self):
        names = {tool["name"] for tool in openai_helper._openai_tools(False, False)}
        self.assertNotIn("http_prefix_oracle", names)
        self.assertNotIn("http_integer_oracle", names)
        visible = {tool["name"] for tool in openai_helper._openai_tools(True, False)}
        self.assertIn("http_prefix_oracle", visible)
        self.assertIn("http_integer_oracle", visible)

    def test_solution_script_is_saved_without_execution_and_restored_on_continue(self):
        case = helper.Case("Save the solver", [])
        output = case.call_tool("save_solution_script", {"name": "solve.py", "code": "print('reproducible')\n"})
        self.assertIn("저장됨", output)
        self.assertEqual((case.root / "solutions" / "solve.py").read_text(encoding="utf-8"),
                         "print('reproducible')\n")
        self.assertIn("입력 오류", case.call_tool("save_solution_script", {"name": "../escape.py", "code": "x"}))
        result = case.finish(helper.DEFAULT_MODEL, "풀이 코드 저장", [])
        self.assertEqual(result["solution_scripts"][0]["name"], "solve.py")
        resumed = helper.Case.from_run(case.id, "새 단서")
        self.assertEqual(resumed.solution_scripts[0]["code"], "print('reproducible')\n")

    def test_http_get_keeps_remote_zip_bytes_and_records_archive_flag(self):
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("flag.txt", "DH{robots_txt_is_not_security}")
        case = helper.Case("웹 문제", [], flag_regex="DH{...}",
                           tcp_endpoint="http://ctf.example:8000/")
        fake_response = MagicMock()
        fake_response.status = 200
        fake_response.headers = {"Content-Type": "application/zip"}
        fake_response.read.return_value = blob.getvalue()
        with patch.object(helper, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value = fake_response
            output = case.http_get("/backup.zip")
        self.assertIn("ZIP 파일 저장", output)
        self.assertIn("DH{robots_txt_is_not_security}", output)
        saved = case.files_dir / "remote_backup.zip"
        self.assertEqual(saved.read_bytes(), blob.getvalue())
        self.assertIn("DH{robots_txt_is_not_security}", case.read_archive_entry(saved.name, "flag.txt"))
        result = case.finish(helper.DEFAULT_MODEL, "", [])
        self.assertEqual(result["remote_observed_flags"], ["DH{robots_txt_is_not_security}"])
        self.assertEqual(len(result["flag_candidates"]), 1)

    def test_endpoint_parser_accepts_pasted_markdown_url_and_nc_command(self):
        self.assertEqual(helper.parse_challenge_endpoint("[주소](http://ctf.example:8080/)"),
                         (None, "http://ctf.example:8080"))
        self.assertEqual(helper.parse_challenge_endpoint("nc ctf.example 31337"),
                         (("ctf.example", 31337), None))
        self.assertEqual(helper.parse_challenge_endpoint("nc -vn ctf.example 31337"),
                         (("ctf.example", 31337), None))
        self.assertEqual(helper.parse_challenge_endpoint("telnet ctf.example 31337"),
                         (("ctf.example", 31337), None))
        self.assertEqual(helper.parse_challenge_endpoint("socat - TCP:ctf.example:31337"),
                         (("ctf.example", 31337), None))
        self.assertEqual(helper.parse_challenge_endpoint("ssh user@ctf.example -p 2222"),
                         (("ctf.example", 2222), None))

    def test_extended_decoders(self):
        case = helper.Case("Test decoders", [])
        # Base32: ACDC{b32} in base32 is IFBUIQ33MIZTE7I=
        res_b32 = case.decode_text("IFBUIQ33MIZTE7I=")
        self.assertIn("base32: ACDC{b32}", res_b32)

        # Hex with spaces and \x: \x41 \x43 \x44 \x43
        res_hex = case.decode_text(r"\x41\x43\x44\x43{hex_test}")
        self.assertIn("hex:", res_hex)
        res_hex_spaces = case.decode_text("41 43 44 43 7b 74 65 73 74 7d")
        self.assertIn("ACDC{test}", res_hex_spaces)

        # URL decode
        res_url = case.decode_text("ACDC%7Burl_flag%7D")
        self.assertIn("url_decode: ACDC{url_flag}", res_url)

        # HTML unescape
        res_html = case.decode_text("ACDC&lbrace;html_flag&rbrace;")
        self.assertIn("html_unescape: ACDC{html_flag}", res_html)

        # Binary string (8-bit ASCII)
        bin_str = "01000001 01000011 01000100 01000011 01111011 01100010 01101001 01101110 01111101"
        res_bin = case.decode_text(bin_str)
        self.assertIn("binary_ascii: ACDC{bin}", res_bin)

        # Single-byte XOR brute force
        xored_hex = bytes(b ^ 0x42 for b in b"ACDC{xor_flag}").hex()
        res_xor = case.decode_text(xored_hex)
        self.assertIn("xor_0x42: ACDC{xor_flag}", res_xor)
        self.assertTrue(any("ACDC{xor_flag}" in item["flag"] for item in case.evidence))

    def test_archive_entry_reader_and_binary_inspection(self):
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, "w") as archive:
            archive.writestr("secret/flag.txt", "ACDC{deep_in_zip}")
            archive.writestr("app.py", "print('hello')")

        # Test UTF-16LE in binary
        utf16_flag = "ACDC{utf16_binary_flag}".encode("utf-16le")
        raw_bin = b"\x7fELF\x02\x01\x01" + b"\0"*9 + b"\x03\0\x3e\0" + b"some_code" + utf16_flag
        case = helper.Case("Inspect", [("chal.zip", blob.getvalue()), ("app.bin", raw_bin)])

        # Read specific entry in zip
        entry_text = case.read_archive_entry("chal.zip", "secret/flag.txt")
        self.assertIn("ACDC{deep_in_zip}", entry_text)
        self.assertTrue(any("ACDC{deep_in_zip}" in item["flag"] for item in case.evidence))

        # Binary analysis detects PIE and extracts UTF-16 flag
        analysis = case.analyze_binary("app.bin")
        self.assertIn("PIE enabled", analysis)
        self.assertIn("ACDC{utf16_binary_flag}", analysis)
        self.assertTrue(any("ACDC{utf16_binary_flag}" in item["flag"] for item in case.evidence))

    def test_hash_calculation(self):
        case = helper.Case("Hash", [("sample.txt", b"hello world\n")])
        res_text = case.hash_calc(text="antigravity")
        self.assertIn("MD5:", res_text)
        self.assertIn("SHA256:", res_text)

        res_file = case.hash_calc(file_name="sample.txt")
        self.assertIn("file=sample.txt", res_file)
        self.assertIn("MD5:", res_file)

    def test_http_post_and_header_preservation(self):
        case = helper.Case("Web post", [], tcp_endpoint="http://ctf.example:8000/")
        fake_response = MagicMock()
        fake_response.status = 200
        fake_response.headers = {"Set-Cookie": "flag=ACDC{cookie_flag}", "Content-Type": "text/html"}
        fake_response.read.return_value = b"success"
        with patch.object(helper, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value = fake_response
            output = case.http_post("/login", body="user=admin", content_type="application/x-www-form-urlencoded")
        self.assertIn("HTTP 200", output)
        self.assertIn("Set-Cookie: flag=ACDC{cookie_flag}", output)
        self.assertTrue(any("ACDC{cookie_flag}" in item["flag"] for item in case.evidence))

    def test_reversing_and_forensics_tools_do_not_execute_uploaded_files(self):
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, "w") as archive:
            archive.writestr("note.txt", "forensic clue")
        elf = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + b"\x02\0\x3e\0" + b"welcome flag string"
        case = helper.Case("inspect", [("challenge.bin", elf), ("evidence.zip", blob.getvalue())], category="reversing")
        self.assertIn("magic=ELF", case.analyze_binary("challenge.bin"))
        self.assertIn("note.txt", case.inspect_archive("evidence.zip"))

    def test_openai_budget_ledger_reserves_and_enforces_limits(self):
        db_path = Path(self.temp.name) / "test_ledger.sqlite3"
        ledger = openai_helper.BudgetLedger(db_path)
        res_id = ledger.reserve("run_1", "gpt-5.4-mini", 500)
        self.assertTrue(res_id)
        total, run = ledger.totals("run_1")
        self.assertGreater(total, 0.0)
        self.assertEqual(total, run)

        usage = SimpleNamespace(input_tokens=100, output_tokens=50, input_tokens_details=SimpleNamespace(cached_tokens=0))
        settled = ledger.settle(res_id, usage)
        self.assertGreater(settled, 0.0)
        total2, _ = ledger.totals()
        self.assertAlmostEqual(total2, settled)

        # Enforce budget limits
        with patch.object(openai_helper, "TOTAL_LIMIT_USD", 0.0001):
            with self.assertRaises(RuntimeError) as cm:
                ledger.reserve("run_2", "gpt-5.4-mini", 500)
            self.assertIn("예산 한도", str(cm.exception))

    def test_openai_solve_mocked(self):
        case = helper.Case("OpenAI puzzle", [("cipher.txt", b"QUNEQ3tvcGVuYWlfa2V5fQ==")])
        call_item = SimpleNamespace(
            type="function_call",
            name="decode_text",
            call_id="call_123",
            arguments=json.dumps({"text": "QUNEQ3tvcGVuYWlfa2V5fQ=="}),
            model_dump=lambda: {"type": "function_call", "name": "decode_text", "call_id": "call_123"}
        )
        resp1 = SimpleNamespace(
            status="completed",
            output=[call_item],
            output_text="",
            usage=SimpleNamespace(input_tokens=200, output_tokens=30, input_tokens_details=None)
        )
        resp2 = SimpleNamespace(
            status="completed",
            output=[],
            output_text="최종 후보는 ACDC{openai_key} 입니다.",
            usage=SimpleNamespace(input_tokens=250, output_tokens=40, input_tokens_details=None)
        )

        fake_client = MagicMock()
        fake_client.responses.create.side_effect = [resp1, resp2]

        with patch("ctf_openai.load_key", return_value="sk-dummykey"), \
             patch("ctf_openai.OpenAI", return_value=fake_client), \
             patch.object(openai_helper, "LEDGER_FILE", Path(self.temp.name) / "ledger.sqlite3"):
            result = case.solve(model="gpt-5.4-mini", max_steps=3)

        self.assertEqual(result["model"], "gpt-5.4-mini")
        self.assertTrue(any("ACDC{openai_key}" in item["flag"] for item in result["flag_candidates"]))
        self.assertIn("cost_usd", result)
        self.assertGreater(result["cost_usd"], 0.0)
        self.assertTrue((case.root / "result.json").exists())

    def test_openai_retries_output_limit_and_records_both_calls(self):
        case = helper.Case("Reasoning-heavy problem", [])
        usage = SimpleNamespace(input_tokens=500, output_tokens=100,
                                input_tokens_details=SimpleNamespace(cached_tokens=0))
        incomplete = SimpleNamespace(status="incomplete", output=[], output_text="",
                                     incomplete_details=SimpleNamespace(reason="max_output_tokens"),
                                     usage=usage)
        completed = SimpleNamespace(status="completed", output=[], output_text="ACDC{retry_ok}",
                                    incomplete_details=None, usage=usage)
        fake_client = MagicMock()
        fake_client.responses.create.side_effect = [incomplete, completed]
        events = []
        case.event = events.append
        ledger_path = Path(self.temp.name) / "retry_ledger.sqlite3"
        with patch("ctf_openai.load_key", return_value="sk-dummykey"), \
             patch("ctf_openai.OpenAI", return_value=fake_client), \
             patch.object(openai_helper, "LEDGER_FILE", ledger_path):
            result = case.solve(model="gpt-5.4", max_steps=1)
        limits = [call.kwargs["max_output_tokens"] for call in fake_client.responses.create.call_args_list]
        self.assertEqual(limits, [openai_helper.MAX_OUTPUT_TOKENS,
                                  openai_helper.RETRY_MAX_OUTPUT_TOKENS])
        self.assertIn("ACDC{retry_ok}", result["answer"])
        self.assertTrue(any("재시도" in event for event in events))
        self.assertGreater(result["cost_usd"], 0)
        import sqlite3
        db = sqlite3.connect(ledger_path)
        try:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM calls WHERE status='charged'").fetchone()[0], 2)
        finally:
            db.close()

    def test_openai_incomplete_other_reason_is_reported_without_retry(self):
        case = helper.Case("Filter reason", [])
        response = SimpleNamespace(status="incomplete", output=[], output_text="",
                                   incomplete_details=SimpleNamespace(reason="content_filter"),
                                   usage=SimpleNamespace(input_tokens=100, output_tokens=10,
                                                         input_tokens_details=None))
        fake_client = MagicMock()
        fake_client.responses.create.return_value = response
        with patch("ctf_openai.load_key", return_value="sk-dummykey"), \
             patch("ctf_openai.OpenAI", return_value=fake_client), \
             patch.object(openai_helper, "LEDGER_FILE", Path(self.temp.name) / "filter_ledger.sqlite3"):
            with self.assertRaisesRegex(RuntimeError, "content_filter"):
                case.solve(model="gpt-5.4", max_steps=1)
        self.assertEqual(fake_client.responses.create.call_count, 1)
        self.assertNotIn("http_get", [tool["name"] for tool in openai_helper._openai_tools(False)])

    def test_step_limits_differ_by_model(self):
        case = helper.Case("Simple step limit test", [])
        with patch.object(helper, "check_model", return_value=None), \
             patch.object(helper, "ollama_request", return_value={"message": {"content": "끝"}}):
            result = case.solve(model=helper.DEFAULT_MODEL, max_steps=40)
            self.assertIn("끝", result["answer"])
        with self.assertRaisesRegex(ValueError, "1~50"):
            case.solve(model=helper.DEFAULT_MODEL, max_steps=55)

        with patch("ctf_openai.load_key", return_value="sk-dummykey"):
            with self.assertRaisesRegex(ValueError, "1~15"):
                case.solve(model="gpt-5.4", max_steps=20)

    def test_local_model_deep_dives_when_flag_not_found(self):
        case = helper.Case("Deep dive test", [("data.txt", b"secret")])
        # 1st call: assistant gives text without tools and without flag -> triggers deep dive reminder
        # 2nd call: assistant calls decode_text
        # 3rd call: assistant returns final answer with flag
        responses = iter([
            {"message": {"role": "assistant", "content": "단순 파일 확인 중입니다."}},
            {"message": {"role": "assistant", "content": "", "tool_calls": [{"type": "function", "function": {
                "name": "decode_text", "arguments": {"text": "QUNEQ3tkZWVwX2RpdmVfc3VjY2Vzc30="}}}]}},
            {"message": {"role": "assistant", "content": "ACDC{deep_dive_success}를 확인했습니다."}}
        ])
        events = []
        case.event = events.append
        def fake_request(path, payload=None, timeout=30):
            if path == "/api/tags":
                return {"models": [{"name": helper.DEFAULT_MODEL}]}
            return next(responses)
        with patch.object(helper, "ollama_request", side_effect=fake_request):
            result = case.solve(max_steps=5)
        self.assertIn("심층 분석 유도", " ".join(events))
        self.assertEqual(result["flag_candidates"][0]["flag"], "ACDC{deep_dive_success}")

    def test_acdc_profile_classifies_fragments_and_decoys(self):
        case = helper.Case("ACDC investigation", [
            ("parts.txt", b"fragment: ACDC{first_part}\ndecoy: ACDC{wrong_value}\n")
        ], profile="acdc-2026", track="security-for-ai")
        self.assertIn("security-for-ai", case.analysis_guidance())
        self.assertEqual([item["role"] for item in case.evidence], ["fragment", "decoy"])
        result = case.finish(helper.DEFAULT_MODEL, "조각의 변환이 필요합니다.", [])
        self.assertEqual(result["flag_candidates"], [])
        self.assertEqual(result["result_status"], "unresolved")
        self.assertEqual(len(result["flag_observations"]), 2)

    def test_model_repeating_fragment_does_not_turn_it_into_candidate(self):
        case = helper.Case("ACDC puzzle", [("parts.txt", b"fragment: ACDC{piece_one}")],
                           profile="acdc-2026")
        result = case.finish(helper.DEFAULT_MODEL, "ACDC{piece_one}는 아직 조각입니다.", [])
        self.assertEqual(result["flag_candidates"], [])
        self.assertEqual(result["flag_observations"][0]["role"], "fragment")

    def test_continuation_restores_files_context_and_profile(self):
        first = helper.Case("ACDC agent puzzle", [("notes.txt", b"fragment: ACDC{piece_one}")],
                            profile="acdc-2026", track="ai-platform-security",
                            tcp_endpoint="http://ctf.example:8080/")
        first.finish(helper.DEFAULT_MODEL, "첫 번째 조각만 확인", [{"tool": "read_file", "result": "piece_one"}])
        resumed = helper.Case.from_run(first.id, "두 번째 응답에서 ACDC{piece_two} 조각 발견")
        self.assertNotEqual(resumed.id, first.id)
        self.assertEqual(resumed.root_id, first.id)
        self.assertEqual(resumed.parent_id, first.id)
        self.assertEqual(resumed.profile, "acdc-2026")
        self.assertEqual(resumed.track, "ai-platform-security")
        self.assertEqual(resumed.web_origin, "http://ctf.example:8080")
        self.assertEqual((resumed.files_dir / "notes.txt").read_bytes(), b"fragment: ACDC{piece_one}")
        self.assertIn("첫 번째 조각만 확인", resumed.continuation_context)
        self.assertEqual(len(resumed.evidence), 2)
        result = resumed.finish(helper.DEFAULT_MODEL, "아직 변환 필요", [])
        self.assertEqual(result["parent_id"], first.id)
        self.assertEqual(result["flag_candidates"], [])

    def test_input_flag_does_not_stop_local_model_before_analysis(self):
        case = helper.Case("ACDC puzzle", [("source.txt", b"ACDC{unverified_input}")])
        responses = iter([
            {"message": {"content": "파일의 문자열은 아직 검증되지 않았습니다."}},
            {"message": {"content": "추가 분석이 필요합니다."}}
        ])
        def fake_request(path, payload=None, timeout=30):
            return {"models": [{"name": helper.DEFAULT_MODEL}]} if path == "/api/tags" else next(responses)
        with patch.object(helper, "ollama_request", side_effect=fake_request) as model_call:
            result = case.solve(max_steps=2)
        self.assertEqual(model_call.call_count, 3)
        self.assertEqual(len([item for item in result["steps"] if "turn" in item]), 2)

    def test_web_api_can_continue_completed_problem_after_reloading_from_disk(self):
        import ctf_helper_web as web

        def post(path, payload):
            raw = json.dumps(payload).encode()
            handler = web.Handler.__new__(web.Handler)
            handler.path = path
            handler.headers = {
                "Host": f"127.0.0.1:{web.PORT}",
                "Origin": f"http://127.0.0.1:{web.PORT}",
                "Content-Length": str(len(raw)),
            }
            handler.rfile = io.BytesIO(raw)
            handler.wfile = io.BytesIO()
            handler.send_response = MagicMock()
            handler.send_header = MagicMock()
            handler.end_headers = MagicMock()
            handler.do_POST()
            self.assertEqual(handler.send_response.call_args.args[0], 202)
            return json.loads(handler.wfile.getvalue())

        def done(job_id):
            for _ in range(40):
                with web.LOCK:
                    job = web.JOBS[job_id].copy()
                if job["status"] == "done":
                    return job["result"]
                if job["status"] == "failed":
                    self.fail(job["error"])
                time.sleep(.05)
            self.fail("analysis job did not finish")

        def fake_ollama(path, payload=None, timeout=30):
            return {"models": [{"name": helper.DEFAULT_MODEL}]} if path == "/api/tags" else {
                "message": {"content": "조각을 더 확인해야 합니다."}}

        with patch.object(web, "RESULTS", Path(self.temp.name)), \
             patch.object(helper, "ollama_request", side_effect=fake_ollama):
            first_job = post("/api/solve", {"description": "ACDC agent puzzle",
                                               "files": [{"name": "challenge/src/main.py", "data": base64.b64encode(b"print(1)").decode()}],
                                               "profile": "acdc-2026", "track": "security-for-ai"})
            first = done(first_job["job_id"])
            self.assertEqual((Path(self.temp.name) / first["run_id"] / "files" /
                              "challenge" / "src" / "main.py").read_bytes(), b"print(1)")
            second_job = post("/api/continue", {"run_id": first["run_id"],
                                                 "note": "새 단서: fragment ACDC{piece_two}"})
            second = done(second_job["job_id"])
            self.assertEqual(second["parent_id"], first["run_id"])
            self.assertEqual(second["profile"], "acdc-2026")
            self.assertEqual(second["flag_candidates"], [])

    def test_local_model_compaction_resets_messages_with_summary(self):
        case = helper.Case("Compaction test", [])
        system_content = "You are a CTF study assistant."
        messages = [
            {"role": "system", "content": system_content},
            {"role": "user", "content": "문제 설명: 암호화 분석\n" + "A" * 30000}
        ]
        fake_summary = (
            "1. [확인된 핵심 단서]: AES-CBC 암호화 확인됨\n"
            "2. [실패한 시도]: 단순 base64 아님\n"
            "3. [발견된 Flag 후보]: 없음\n"
            "4. [다음 분석 계획]: 키 파일 탐색"
        )
        def fake_request(path, payload=None, timeout=30):
            return {"message": {"content": fake_summary}}
        with patch.object(helper, "ollama_request", side_effect=fake_request):
            compacted = case._compact_messages(helper.DEFAULT_MODEL, system_content, messages)
        self.assertEqual(len(compacted), 2)
        self.assertEqual(compacted[0]["role"], "system")
        self.assertEqual(compacted[1]["role"], "user")
        self.assertIn("AES-CBC 암호화 확인됨", compacted[1]["content"])
        self.assertIn("키 파일 탐색", compacted[1]["content"])


if __name__ == "__main__":
    unittest.main()
