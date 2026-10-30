// Dependency-free regression for the continuation result display.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
  constructor(id = '') {
    this.id = id;
    this.value = '';
    this.textContent = '';
    this.hidden = false;
    this.disabled = false;
    this.children = [];
    this.options = [];
    this.listeners = {};
    this.classList = {add() {}, remove() {}};
    this.style = {};
  }
  addEventListener(name, handler) { this.listeners[name] = handler; }
  replaceChildren(...children) {
    this.children = children;
    if (this.id === 'history-select') this.options = children;
  }
  append(...children) {
    this.children.push(...children);
    if (this.id === 'history-select') this.options.push(...children);
  }
  querySelectorAll(selector) { return selector === 'option' ? this.options : []; }
}

const elements = new Map();
const get = id => {
  if (!elements.has(id)) elements.set(id, new Element(id));
  return elements.get(id);
};
get('model').options = [
  Object.assign(new Element(), {value: 'lab-qwen3-8b-16k:locked'}),
  Object.assign(new Element(), {value: 'gpt-5.4-mini'}),
  Object.assign(new Element(), {value: 'gpt-5.4'}),
  Object.assign(new Element(), {value: 'airllm:qwen3-14b', disabled: true}),
];
get('model').value = 'lab-qwen3-8b-16k:locked';

const oldRun = '20261030_000000_aaaaaaaa';
const newRun = '20261030_000001_bbbbbbbb';
const result = (id, parentId, answer) => ({
  run_id: id, parent_id: parentId, answer, model: 'gpt-5.4',
  flag_candidates: [], flag_observations: [], requests: [], solution_scripts: [],
});
let newJobPolls = 0;
const calls = [];
const fetch = async (url, options = {}) => {
  calls.push(url);
  if (url === '/api/health') return {ok: true, json: async () => ({
    ollama: {model: 'lab-qwen3-8b-16k:locked', ready: false},
    openai: {ready: true, remaining: 29, limit: 30},
    airllm: {ready: true, state: 'ready', model: 'airllm:qwen3-14b'},
  })};
  if (url === '/api/history') return {ok: true, json: async () => [
    {id: newRun, time: '20261030_000001', model: 'gpt-5.4', flags: [], preview: 'continued'},
    {id: oldRun, time: '20261030_000000', model: 'gpt-5.4', flags: [], preview: 'original'},
  ]};
  if (url === '/api/continue') {
    const body = JSON.parse(options.body);
    assert.equal(body.run_id, oldRun);
    assert.equal(body.note, '새 단서');
    assert.equal(body.model, 'gpt-5.4');
    return {ok: true, json: async () => ({job_id: newRun})};
  }
  if (url === `/api/job/${oldRun}`) return {ok: true, json: async () => ({
    status: 'done', result: result(oldRun, null, '이전 답변'), events: [],
  })};
  if (url === `/api/job/${newRun}`) {
    newJobPolls += 1;
    if (newJobPolls === 1) throw new Error('temporary disconnect');
    if (newJobPolls === 2) return {ok: true, json: async () => ({
      status: 'running', result: null, events: ['이어 분석 중'],
    })};
    return {ok: true, json: async () => ({
      status: 'done', result: result(newRun, oldRun, '새 답변'), events: ['완료'],
    })};
  }
  throw new Error(`unexpected fetch: ${url}`);
};

const timers = new Map();
let nextTimer = 1;
const context = {
  document: {getElementById: get, createElement: () => new Element()},
  navigator: {clipboard: {writeText: async () => {}}},
  fetch,
  setTimeout: callback => { const id = nextTimer++; timers.set(id, callback); return id; },
  clearTimeout: id => timers.delete(id),
  console,
};
const script = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'ctf_helper.js'), 'utf8');
vm.runInNewContext(script, context, {filename: 'ctf_helper.js'});
const flush = async () => { for (let n = 0; n < 15; n++) await Promise.resolve(); };
const fireTimer = async () => {
  assert.ok(timers.size, 'expected a scheduled result poll');
  const [id, callback] = timers.entries().next().value;
  timers.delete(id);
  callback();
  await flush();
  assert.equal(get('model').options.find(option => option.value === 'airllm:qwen3-14b').disabled, false);
  assert.match(get('health-airllm').textContent, /준비됨/);
};

(async () => {
  await flush();
  get('history-select').value = oldRun;
  get('history-select').listeners.change();
  await flush();
  assert.match(get('answer').textContent, /이전 답변/);
  assert.equal(get('model').value, 'gpt-5.4');
  assert.equal(get('continue-panel').hidden, false);

  get('continue-note').value = '새 단서';
  await get('continue-btn').listeners.click();
  await flush();
  assert.equal(get('result').hidden, false);
  assert.match(get('answer').textContent, new RegExp(newRun));
  assert.doesNotMatch(get('answer').textContent, /이전 답변/);
  assert.equal(get('continue-note').value, '새 단서');
  assert.match(get('status').textContent, /재시도/);

  await fireTimer();
  assert.match(get('status').textContent, /분석 진행 중/);
  await fireTimer();
  assert.match(get('answer').textContent, /새 답변/);
  assert.match(get('answer').textContent, new RegExp(newRun));
  assert.equal(get('history-select').value, newRun);
  assert.equal(get('continue-note').value, '');
  assert.equal(get('continue-panel').hidden, false);
  assert.ok(calls.includes('/api/continue'));
  console.log('Continuation UI regression passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
