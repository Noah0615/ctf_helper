"""Worker protocol and real CTF agent routing, without downloading 14B weights."""
from contextlib import nullcontext
import io
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ctf_airllm as client
import ctf_airllm_server as worker
import ctf_helper as helper

TOOLS = [{"type": "function", "function": {"name": "read_file", "parameters": {"type": "object"}}}]


class AirLLMTests(unittest.TestCase):
    def test_qwen_thinking_and_tool_output(self):
        message = worker.parse_output('reasoning</think>\n<tool_call>{"name":"read_file","arguments":{"name":"a.txt"}}</tool_call>', TOOLS, True)
        self.assertEqual(message["thinking"], "reasoning")
        self.assertEqual(message["tool_calls"][0]["function"], {"name": "read_file", "arguments": {"name": "a.txt"}})
        self.assertEqual(message["content"], "")
        self.assertEqual(worker.parse_output("최종 답변", [])['content'], "최종 답변")

    def test_incomplete_or_unlisted_tool_never_becomes_executable(self):
        for text in ['<tool_call>{"name":"shell","arguments":{}}</tool_call>',
                     '<tool_call>{"name":"read_file","arguments":[]}</tool_call>',
                     '<tool_call>{"name":"read_file"}']:
            with self.assertRaises(ValueError):
                worker.parse_output(text, TOOLS)
        with self.assertRaisesRegex(ValueError, "추론"):
            worker.parse_output("unfinished thinking", TOOLS, True)

    def test_local_only_url_and_unavailable_status(self):
        with patch.dict('os.environ', {"CTF_AIRLLM_URL": "https://example.com"}):
            self.assertFalse(client.health()["ready"])
            with self.assertRaisesRegex(ValueError, "로컬"):
                client.base_url()
        with patch.object(client, "request", side_effect=RuntimeError("offline")):
            with self.assertRaisesRegex(RuntimeError, "준비 필요"):
                client.check_model()
        with patch.object(client, 'request', return_value={'model': 'another-model', 'message': {}}):
            with self.assertRaisesRegex(RuntimeError, '모델 ID'):
                client.chat({'model': client.AIRLLM_MODEL})

    def test_agent_executes_airllm_tool_then_saves_result(self):
        (helper.ROOT / '.runtime').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=helper.ROOT / '.runtime') as folder, patch.object(helper, 'RESULTS', Path(folder)), \
             patch.object(helper, 'check_airllm_model', return_value={"ready": True, "context": 8192}), \
             patch.object(helper, 'ollama_request', side_effect=AssertionError("must not call Ollama")), \
             patch.object(helper, 'airllm_chat', side_effect=[
                 {"message": {"content": "", "tool_calls": [{"function": {"name": "read_file", "arguments": {"name": "hint.txt"}}}]}},
                 {"message": {"content": "첨부 파일 분석 완료"}},
             ]) as chat:
            case = helper.Case("Analyze the local supplied hint", [("hint.txt", b"a local hint")])
            result = case.solve(model=client.AIRLLM_MODEL, max_steps=2)
            self.assertEqual(result['model'], client.AIRLLM_MODEL)
            self.assertTrue(any(s.get('tool') == 'read_file' for s in result['steps']))
            self.assertTrue(any('a local hint' in m.get('content', '') and m['role'] == 'tool'
                                for m in chat.call_args_list[1].args[0]['messages']))
            self.assertIn('첨부 파일 분석 완료', json.loads((case.root/'result.json').read_text(encoding='utf-8'))['answer'])

    def test_worker_uses_template_and_only_decodes_new_tokens(self):
        input_ids = SimpleNamespace(shape=(1, 3), to=lambda device: 'input-on-cuda')
        tokenizer = Mock()
        tokenizer.apply_chat_template.return_value = 'prompt with tools'
        tokenizer.return_value = {"input_ids": input_ids}
        tokenizer.decode.return_value = '<tool_call>{"name":"read_file","arguments":{"name":"x"}}</tool_call>'
        tokenizer.eos_token_id = 1
        model = SimpleNamespace(tokenizer=tokenizer, device='cuda:0', generate=Mock(return_value=SimpleNamespace(sequences=[[10, 11, 12, 20, 21]])))
        engine = worker.Engine(Path('.runtime/test-only'), context=128, max_new_tokens=16)
        engine.model = model
        with patch.dict(sys.modules, {"torch": SimpleNamespace(inference_mode=nullcontext)}):
            response = engine.chat({"model": client.AIRLLM_MODEL, "messages": [{"role": "user", "content": "test"}], "tools": TOOLS})
        tokenizer.decode.assert_called_once_with([20, 21], skip_special_tokens=False)
        self.assertEqual(response['prompt_eval_count'], 3)
        self.assertEqual(response['eval_count'], 2)
        self.assertTrue(tokenizer.apply_chat_template.call_args.kwargs['tools'])
        self.assertFalse(tokenizer.call_args.kwargs.get('truncation', False))
        self.assertEqual(engine.state, 'ready')
        engine.context = 4
        with patch.dict(sys.modules, {"torch": SimpleNamespace(inference_mode=nullcontext)}):
            with self.assertRaisesRegex(ValueError, "컨텍스트"):
                engine.chat({"model": client.AIRLLM_MODEL, "messages": [{"role": "user", "content": "test"}]})
        self.assertEqual(model.generate.call_count, 1)

    def test_web_continuation_keeps_airllm_model_and_deep_mode(self):
        import ctf_helper_web as web
        (helper.ROOT / '.runtime').mkdir(exist_ok=True)
        def post(payload):
            raw = json.dumps(payload).encode()
            handler = web.Handler.__new__(web.Handler)
            handler.path = '/api/continue'
            handler.headers = {'Host': f'127.0.0.1:{web.PORT}', 'Origin': f'http://127.0.0.1:{web.PORT}', 'Content-Length': str(len(raw))}
            handler.rfile, handler.wfile = io.BytesIO(raw), io.BytesIO()
            handler.send_response, handler.send_header, handler.end_headers = Mock(), Mock(), Mock()
            handler.do_POST()
            return handler.send_response.call_args.args[0], json.loads(handler.wfile.getvalue())
        with tempfile.TemporaryDirectory(dir=helper.ROOT / '.runtime') as folder, patch.object(helper, 'RESULTS', Path(folder)):
            parent = helper.Case('Local synthetic fixture', [('hint.txt', b'fixture')])
            parent.finish(helper.DEFAULT_MODEL, 'first answer', [])
            payload = {'run_id': parent.id, 'note': 'new local hint', 'model': client.AIRLLM_MODEL, 'think_mode': 'deep'}
            with patch.object(web, 'check_airllm_model', side_effect=RuntimeError('worker offline')):
                code, data = post(payload)
                self.assertEqual(code, 400)
                self.assertIn('offline', data['error'])
            with patch.object(web, 'check_airllm_model', return_value={'ready': True}), \
                 patch.object(helper.Case, 'solve', return_value={'answer': 'next answer'}) as solve:
                code, data = post(payload)
                self.assertEqual(code, 202)
                for _ in range(40):
                    with web.LOCK:
                        status = web.JOBS[data['job_id']]['status']
                    if status in {'done', 'failed'}:
                        break
                    time.sleep(.02)
                self.assertEqual(status, 'done')
                solve.assert_called_once_with(model=client.AIRLLM_MODEL, think_mode='deep')
            with web.LOCK:
                web.JOBS.pop(data['job_id'], None)


if __name__ == '__main__':
    unittest.main()
