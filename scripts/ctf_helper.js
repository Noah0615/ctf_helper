const $ = id => document.getElementById(id);
let currentRunId = null;
let activeJobId = null;
let pollTimer = null;
let pollFailures = 0;
let continuationSourceId = null;

const CATEGORY_HINTS = {
  auto: "문제 설명과 첨부 파일을 분석하여 최적의 분석 흐름을 자동으로 결정합니다.",
  web: "웹 소스(라우트, 템플릿, Dockerfile), 환경 변수, robots.txt 분석. 필요 시 http_get / http_post 도구로 서버 응답 확인.",
  pwn: "바이너리 아키텍처, 보호 기법(PIE, Canary, NX), 버퍼 및 포맷스트링 취약점 분석. (실행 불가, 정적 분석 전용)",
  reversing: "파일 매직, 엔트로피, 인쇄 가능 문자열(ASCII/UTF-16LE), 디스어셈블리 및 상수/인코딩 분석.",
  crypto: "암호 알고리즘(RSA, AES, XOR, PRNG), 취약한 키/파라미터 분석. decode_text 및 오프라인 Python 계산 활용.",
  forensics: "파일 시그니처, 메타데이터, 아카이브 구조(inspect_archive, read_archive_entry), 바이너리 문자열 검사.",
  "ai-security": "AI ?? ??: ?? ???(SafeTensors, GGUF, Pickle) ??, ???? RCE ??, ???? ???(??/?? ???/??? ??) ?? ?? ? ??.",
  "cloud-web3": "클라우드 IAM 정책, Docker/K8s 설정, 스마트 컨트랙트 재진입/정수 연산 및 환경 변수 분석.",
  other: "문제 설명 및 첨부 파일 중심 범용 정적 분석."
};

$('category').addEventListener('change', () => {
  const cat = $('category').value;
  $('cat-hint').textContent = CATEGORY_HINTS[cat] || CATEGORY_HINTS.auto;
});

function detectEndpoint(text) {
  if (!text) return null;
  const found = [];
  for (const match of text.matchAll(/https?:\/\/[^\s)\]>,]+/gi)) found.push({at: match.index, value: match[0]});
  for (const match of text.matchAll(/\b(?:nc|ncat|telnet)\s+(?:-[a-zA-Z0-9]+\s+)*([A-Za-z0-9.-]+)\s+(\d{1,5})\b/gi))
    found.push({at: match.index, value: `${match[1]}:${match[2]}`});
  for (const match of text.matchAll(/TCP:([A-Za-z0-9.-]+):(\d{1,5})/gi))
    found.push({at: match.index, value: `${match[1]}:${match[2]}`});
  for (const match of text.matchAll(/\bssh\s+(?:-p\s*(\d{1,5})\s+)?(?:[A-Za-z0-9_.-]+@)?([A-Za-z0-9.-]+)(?:\s+-p\s*(\d{1,5}))?\b/gi))
    if (match[1] || match[3]) found.push({at: match.index, value: `${match[2]}:${match[1] || match[3]}`});
  if (found.length) return found.sort((a, b) => a.at - b.at).at(-1).value;
  const plain = [...text.matchAll(/\b([A-Za-z0-9.-]+\.[A-Za-z]{2,}):(\d{2,5})\b/gi)];
  return plain.length ? `${plain.at(-1)[1]}:${plain.at(-1)[2]}` : null;
}

let endpointAutoFilled = false;
$('tcp-endpoint').addEventListener('input', () => { endpointAutoFilled = false; });
$('description').addEventListener('input', () => {
  if ($('tcp-endpoint').value.trim() && !endpointAutoFilled) return;
  const ep = detectEndpoint($('description').value);
  if (ep) { $('tcp-endpoint').value = ep; endpointAutoFilled = true; }
  else if (endpointAutoFilled) { $('tcp-endpoint').value = ''; endpointAutoFilled = false; }
});

// Preserve relative paths for files selected from folders or dropped directories.
const MAX_FILES = 256;
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const MAX_TOTAL_BYTES = 96 * 1024 * 1024;
let selectedFiles = [];

function addSelectedFiles(items) {
  const byPath = new Map(selectedFiles.map(item => [item.path.toLowerCase(), item]));
  for (const item of items) byPath.set(item.path.toLowerCase(), item);
  selectedFiles = [...byPath.values()];
  updateFileList();
}

function updateFileList() {
  const listEl = $('file-list');
  listEl.replaceChildren();
  if (!selectedFiles.length) return;
  const total = selectedFiles.reduce((sum, item) => sum + item.file.size, 0);
  const summary = document.createElement('div');
  summary.textContent = `파일 ${selectedFiles.length}개 · 합계 ${(total / (1024 * 1024)).toFixed(2)} MiB`;
  listEl.append(summary);
  for (const {file, path} of selectedFiles) {
    const badge = document.createElement('span');
    badge.className = 'file-badge';
    const size = file.size >= 1024 * 1024
      ? `${(file.size / (1024 * 1024)).toFixed(2)} MiB`
      : `${(file.size / 1024).toFixed(1)} KiB`;
    badge.textContent = `${path} (${size})`;
    listEl.append(badge);
  }
}
$('pick-files').addEventListener('click', () => $('files').click());
$('pick-folder').addEventListener('click', () => $('folder-files').click());
$('files').addEventListener('change', () => {
  addSelectedFiles([...$('files').files].map(file => ({file, path: file.name})));
  $('files').value = '';
});
$('folder-files').addEventListener('change', () => {
  addSelectedFiles([...$('folder-files').files].map(file =>
    ({file, path: file.webkitRelativePath || file.name})));
  $('folder-files').value = '';
});

async function filesInEntry(entry, prefix = '') {
  if (entry.isFile) {
    const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
    return [{file, path: prefix + file.name}];
  }
  if (!entry.isDirectory) return [];
  const reader = entry.createReader();
  const children = [];
  while (true) {
    const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
    if (!batch.length) break;
    children.push(...batch);
  }
  const nested = await Promise.all(children.map(child => filesInEntry(child, prefix + entry.name + '/')));
  return nested.flat();
}

const dropZone = $('drop-zone');
['dragenter', 'dragover'].forEach(name => {
  dropZone.addEventListener(name, e => { e.preventDefault(); dropZone.classList.add('dragover'); });
});
['dragleave', 'drop'].forEach(name => {
  dropZone.addEventListener(name, e => { e.preventDefault(); dropZone.classList.remove('dragover'); });
});
dropZone.addEventListener('drop', async e => {
  if (!e.dataTransfer) return;
  try {
    const entries = [...(e.dataTransfer.items || [])]
      .filter(item => item.kind === 'file')
      .map(item => item.getAsEntry?.() || item.webkitGetAsEntry?.())
      .filter(Boolean);
    const picked = entries.length
      ? (await Promise.all(entries.map(entry => filesInEntry(entry)))).flat()
      : [...e.dataTransfer.files].map(file => ({file, path: file.name}));
    addSelectedFiles(picked);
  } catch (error) {
    $('status').textContent = `폴더 읽기 실패: ${error.message}`;
  }
});

// Keyboard shortcut (Ctrl+Enter)
['description', 'code'].forEach(id => {
  $(id).addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      $('form').requestSubmit();
    }
  });
});

// Reset button
$('reset-btn').addEventListener('click', () => {
  activeJobId = null;
  continuationSourceId = null;
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
  $('form').reset();
  endpointAutoFilled = false;
  $('cat-hint').textContent = CATEGORY_HINTS.auto;
  $('file-list').replaceChildren();
  selectedFiles = [];
  $('result').hidden = true;
  $('status').textContent = '';
  $('flags').replaceChildren();
  $('answer').textContent = '';
  $('solutions').textContent = '';
  $('solutions-details').hidden = true;
  $('events').textContent = '';
  $('request-log').textContent = '';
  $('continue-panel').hidden = true;
  $('continue-note').value = '';
  currentRunId = null;
});

// Copy full report
$('copy-report-btn').addEventListener('click', () => {
  const flags = Array.from($('flags').querySelectorAll('.flag-text')).map(el => el.textContent).join('\n');
  const answer = $('answer').textContent;
  const fullText = `=== CTF 분석 결과 ===\n\n[발견된 Flag]\n${flags || '(없음)'}\n\n[상세 내용]\n${answer}`;
  navigator.clipboard.writeText(fullText);
  const btn = $('copy-report-btn');
  btn.textContent = '복사 완료!';
  btn.classList.add('copied');
  setTimeout(() => { btn.textContent = '전체 결과 복사'; btn.classList.remove('copied'); }, 1500);
});

$('copy-solutions-btn').addEventListener('click', () => {
  navigator.clipboard.writeText($('solutions').textContent);
});

async function loadHistory(selectedId = null) {
  try {
    const list = await (await fetch('/api/history')).json();
    const sel = $('history-select');
    const wanted = selectedId || sel.value;
    sel.replaceChildren();
    const defaultOpt = document.createElement('option');
    defaultOpt.value = "";
    defaultOpt.textContent = "🕒 최근 분석 기록 선택...";
    sel.append(defaultOpt);
    for (const item of list) {
      const opt = document.createElement('option');
      opt.value = item.id;
      const flagInfo = item.flags.length ? `[Flag ${item.flags.length}개] ` : '';
      const preview = item.preview ? ` - ${item.preview.slice(0, 30)}` : '';
      opt.textContent = `${flagInfo}${item.time} (${item.model})${preview}`;
      sel.append(opt);
    }
    if (wanted && [...sel.options].some(option => option.value === wanted)) sel.value = wanted;
  } catch (e) {
    // Ignore history errors
  }
}

$('history-select').addEventListener('change', () => {
  const id = $('history-select').value;
  if (!id) return;
  startTracking(id, 'history');
});

async function health() {
  try {
    const r = await (await fetch('/api/health')).json();
    const ollamaEl = $('health-ollama');
    const openaiEl = $('health-openai');
    const airllm = r.airllm;
    const airllmEl = $('health-airllm');
    const airllmOption = [...$('model').options].find(option => option.value === 'airllm:qwen3-14b');
    if (airllmEl) {
      airllmEl.textContent = airllm?.ready ? `AirLLM: 준비됨 · Qwen3-14B${airllm.state === 'generating' ? ' · 생성 중' : ''}`
        : airllm?.state === 'loading' ? 'AirLLM: 다운로드·레이어 변환 중…' : 'AirLLM: 별도 서버 준비 필요';
      airllmEl.className = `health-pill ${airllm?.ready ? 'health-ok' : 'health-warn'}`;
      airllmEl.title = airllm?.error || '';
    }
    if (airllmOption) {
      airllmOption.disabled = !airllm?.ready;
      airllmOption.textContent = airllm?.ready ? 'AirLLM Qwen3-14B (로컬 · 레이어 스트리밍, 느림)'
        : 'AirLLM Qwen3-14B (별도 서버 준비 필요)';
    }
    if (r.ollama?.model) $('model').options[0].value = r.ollama.model;

    if (r.ollama && r.ollama.ready) {
      ollamaEl.textContent = `Ollama: 준비됨 · ${r.ollama.model}`;
      ollamaEl.className = 'health-pill health-ok';
    } else {
      ollamaEl.textContent = `Ollama: 연결 필요`;
      ollamaEl.className = 'health-pill health-warn';
      if (r.ollama && r.ollama.error) ollamaEl.title = r.ollama.error;
    }

    if (r.openai && r.openai.ready) {
      openaiEl.textContent = `OpenAI API 키 설정됨 · 남은 한도 $${r.openai.remaining.toFixed(2)} / $${r.openai.limit.toFixed(2)}`;
      openaiEl.className = 'health-pill health-ok';
    } else {
      openaiEl.textContent = `OpenAI API: OPENAI_API_KEY 환경 변수 필요`;
      openaiEl.className = 'health-pill health-warn';
      const opts = $('model').querySelectorAll('option');
      opts.forEach(opt => {
        if (opt.value.startsWith('gpt-')) {
          opt.disabled = true;
          opt.textContent += ' (키 없음)';
        }
      });
    }
  } catch (e) {
    $('health-ollama').textContent = `상태 확인 실패: ${e.message}`;
  }
}

function schedulePoll(id, delay = 1500) {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = setTimeout(() => poll(id), delay);
}

function startTracking(id, mode = 'new', parentId = null) {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
  activeJobId = id;
  pollFailures = 0;
  continuationSourceId = mode === 'continue' ? parentId : null;
  $('result').hidden = false;
  $('cost').hidden = true;
  $('flags').replaceChildren();
  $('answer').textContent = `새 실행 ID: ${id}\n결과를 기다리는 중입니다.`;
  $('solutions').textContent = '';
  $('solutions-details').hidden = true;
  $('request-log').textContent = '';
  $('events').textContent = '';
  $('status').textContent = mode === 'continue' ? '이어서 분석 중…'
    : mode === 'history' ? '저장된 분석 기록 불러오는 중…' : '분석 시작됨…';
  $('submit').disabled = true;
  $('continue-btn').disabled = true;
  poll(id);
}

async function poll(id) {
  if (activeJobId !== id) return;
  try {
  const response = await fetch(`/api/job/${encodeURIComponent(id)}`, {cache: 'no-store'});
  if (!response.ok) throw new Error(`결과 조회 HTTP ${response.status}`);
  const r = await response.json();
  if (activeJobId !== id) return;
  pollFailures = 0;
  if (r.status === 'done' && !r.result) throw new Error('완료된 결과 본문이 없습니다.');
  const items = r.result?.flag_candidates || [];
  const observations = r.result?.flag_observations || [];
  const remote = items.filter(item => item.source.startsWith('문제 웹 응답:') || item.source.startsWith('문제 서버:'));
  const remoteValues = new Set(remote.map(item => item.flag));
  const others = items.filter(item => !remoteValues.has(item.flag));
  $('status').textContent = r.status === 'done'
    ? (remote.length ? '분석 완료 · 문제 서버에서 후보 문자열 관찰'
       : others.length ? '분석 완료 · 미검증 후보 발견' : '분석 완료 · 정확한 flag 미확인')
    : r.status === 'running' ? '분석 진행 중…' : `상태: ${r.status}`;
  $('events').textContent = (r.events || []).join('\n');

  // Handle pause / resume buttons
  const pauseBtn = $('pause-btn');
  const resumeBtn = $('resume-btn');
  if (r.status === 'running') {
    if (pauseBtn) { pauseBtn.style.display = 'inline-block'; pauseBtn.disabled = false; }
    if (resumeBtn) { resumeBtn.style.display = 'none'; }
  } else if (r.status === 'paused') {
    if (pauseBtn) { pauseBtn.style.display = 'none'; }
    if (resumeBtn) { resumeBtn.style.display = 'inline-block'; resumeBtn.disabled = false; }
  } else {
    if (pauseBtn) pauseBtn.style.display = 'none';
    if (resumeBtn) resumeBtn.style.display = 'none';
  }

  // Display hypotheses if present
  const hypList = r.hypotheses || r.result?.hypotheses;
  if (hypList && hypList.length) {
    const box = $('hypotheses-box');
    const list = $('hypotheses-list');
    if (box && list) {
      box.style.display = 'block';
      list.replaceChildren();
      for (const h of hypList) {
        const d = document.createElement('div');
        d.className = 'hyp-item';
        const badge = document.createElement('span');
        badge.className = `hyp-status status-${h.status || 'pending'}`;
        badge.textContent = (h.status || 'pending').toUpperCase();
        const titleSpan = document.createElement('strong');
        titleSpan.textContent = (h.title || '') + ' ';
        const descSpan = document.createElement('span');
        descSpan.textContent = `(도구: ${h.next_tool} | 사유: ${h.reason})`;
        d.append(badge, titleSpan, descSpan);
        list.append(d);
      }
    }
  }
  if (r.status === 'done') {
    $('flags').replaceChildren();
    function addGroup(title, group, kind = 'candidate') {
      if (!group.length) return;
      const heading = document.createElement('h3');
      heading.textContent = title;
      $('flags').append(heading);
      const seen = new Set();
      for (const item of group) {
      if (seen.has(item.flag)) continue;
      seen.add(item.flag);
      const block = document.createElement('div');
      block.className = 'flag-item';

      const flagSpan = document.createElement('span');
      flagSpan.className = kind === 'candidate' ? 'flag-text' : 'flag-observation-text';
      flagSpan.textContent = item.flag;

      const copyBtn = document.createElement('button');
      copyBtn.type = 'button';
      copyBtn.className = 'copy-btn';
      copyBtn.textContent = '복사';
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(item.flag);
        copyBtn.textContent = '복사됨!';
        copyBtn.classList.add('copied');
        setTimeout(() => { copyBtn.textContent = '복사'; copyBtn.classList.remove('copied'); }, 1500);
      };

      const metaSpan = document.createElement('span');
      metaSpan.className = 'flag-meta';
      metaSpan.textContent = `— ${item.status} (${item.source})`;

      block.append(flagSpan, copyBtn, metaSpan);
      $('flags').append(block);
      }
    }
    addGroup('문제 서버 응답에서 확인한 값', remote);
    addGroup('추가 후보 · 공식 채점 미확인', others);
    addGroup('조각 · 변환 또는 결합 필요', observations.filter(item => item.role === 'fragment'), 'observation');
    addGroup('미끼로 표시된 문자열', observations.filter(item => item.role === 'decoy'), 'observation');
    if (!observations.length && !items.length) $('flags').textContent = '관찰된 flag 형식 문자열이 없습니다. 문제 주소와 첨부 파일을 확인하세요.';

    if (r.result.cost_usd !== undefined) {
      $('cost').hidden = false;
      $('cost').textContent = `모델: ${r.result.model} · 과금: $${r.result.cost_usd.toFixed(4)} USD`;
    } else {
      $('cost').hidden = false;
      $('cost').textContent = `모델: ${r.result.model} (로컬 실행)`;
    }

    $('answer').textContent = r.result.answer + `\n\n실행 ID: ${r.result.run_id}`;
    const matchingModel = [...$('model').options].find(option => option.value === r.result.model);
    if (matchingModel && !matchingModel.disabled) $('model').value = r.result.model;
    const scripts = r.result.solution_scripts || [];
    $('solutions').textContent = scripts.map(item => `### ${item.name}\n${item.code}`).join('\n\n');
    $('solutions-details').hidden = scripts.length === 0;
    if (r.result.parent_id) $('answer').textContent += `\n이전 실행 ID: ${r.result.parent_id}`;
    $('request-log').textContent = (r.result.requests || []).map(entry =>
      `${entry.at} ${entry.method} ${entry.path}\n${entry.request_body_preview || ''}\n${entry.response}`).join('\n\n') || '이 실행에서 기록된 요청이 없습니다.';
    activeJobId = null;
    pollTimer = null;
    continuationSourceId = null;
    currentRunId = r.result.run_id;
    $('continue-note').value = '';
    $('continue-panel').hidden = false;
    $('continue-btn').disabled = false;
    $('submit').disabled = false;
    health();
    loadHistory(r.result.run_id);
  } else if (r.status === 'failed') {
    activeJobId = null;
    pollTimer = null;
    $('status').textContent = continuationSourceId ? '이어 분석 실패' : '분석 실패';
    $('answer').textContent = `분석 실패: ${r.error}`;
    $('submit').disabled = false;
    if (continuationSourceId) {
      currentRunId = continuationSourceId;
      $('continue-panel').hidden = false;
      $('continue-btn').disabled = false;
      continuationSourceId = null;
    }
  } else {
    schedulePoll(id);
  }
  } catch (error) {
    if (activeJobId !== id) return;
    pollFailures += 1;
    if (pollFailures >= 12) {
      activeJobId = null;
      pollTimer = null;
      $('status').textContent = '결과 자동 조회 실패';
      $('answer').textContent = `실행 ID: ${id}\n서버 연결 상태를 확인한 뒤 최근 분석 기록에서 이 실행을 다시 선택하세요. ${error.message}`;
      $('submit').disabled = false;
      if (continuationSourceId) {
        currentRunId = continuationSourceId;
        $('continue-panel').hidden = false;
        $('continue-btn').disabled = false;
        continuationSourceId = null;
      }
      return;
    }
    $('status').textContent = `결과 조회 재시도 중… (${pollFailures}회)`;
    $('answer').textContent = `새 실행 ID: ${id}\n서버 연결이 회복되면 결과를 자동으로 표시합니다. ${error.message}`;
    schedulePoll(id, Math.min(5000, 1500 + pollFailures * 500));
  }
}

$('form').addEventListener('submit', async event => {
  event.preventDefault();
  currentRunId = null;
  $('continue-panel').hidden = true;
  $('submit').disabled = true;
  $('result').hidden = false;
  $('cost').hidden = true;
  $('status').textContent = '파일 읽는 중…';
  $('events').textContent = '';
  $('flags').replaceChildren();
  $('answer').textContent = '';
  $('solutions').textContent = '';
  $('solutions-details').hidden = true;
  try {
    const picked = selectedFiles;
    if (picked.length > MAX_FILES || picked.some(({file}) => file.size > MAX_FILE_BYTES) ||
        picked.reduce((sum, {file}) => sum + file.size, 0) > MAX_TOTAL_BYTES)
      throw new Error('파일은 최대 256개, 파일당 32 MiB, 합계 96 MiB까지 허용됩니다.');
    const files = [];
    for (const {file, path} of picked) {
      $('status').textContent = `파일 읽는 중… ${files.length + 1}/${picked.length}`;
      const data = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result).split(',')[1]);
        reader.onerror = () => reject(reader.error);
        reader.readAsDataURL(file);
      });
      files.push({name: path, data});
    }
    if ($('code').value.trim()) {
      if (files.some(file => file.name.toLowerCase() === 'pasted_code.txt'))
        throw new Error('pasted_code.txt 파일 이름이 붙여넣은 코드와 중복됩니다.');
      const bytes = new TextEncoder().encode($('code').value);
      if (bytes.length > MAX_FILE_BYTES) throw new Error('붙여넣은 코드가 32 MiB를 초과했습니다.');
      if (picked.length + 1 > MAX_FILES ||
          picked.reduce((sum, {file}) => sum + file.size, bytes.length) > MAX_TOTAL_BYTES)
        throw new Error('첨부 파일과 붙여넣은 코드는 합계 256개, 96 MiB를 초과할 수 없습니다.');
      let binary = '';
      for (const byte of bytes) binary += String.fromCharCode(byte);
      files.push({name: 'pasted_code.txt', data: btoa(binary)});
    }
    const response = await fetch('/api/solve', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        description: $('description').value,
        files,
        model: $('model').value,
        think_mode: $('think-mode') ? $('think-mode').value : 'quick',
        category: $('category').value,
        profile: $('profile').value,
        track: $('track').value,
        challenge_mode: $('challenge-mode').value,
        tcp_endpoint: $('tcp-endpoint').value.trim(),
        allow_mismatch: Boolean($('allow-mismatch')?.checked),
        flag_regex: $('regex').value,
        docker_python: $('python').checked
      })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    startTracking(result.job_id);
  } catch (e) {
    $('status').textContent = '시작 실패';
    $('answer').textContent = e.message;
    $('submit').disabled = false;
  }
});

$('continue-btn').addEventListener('click', async () => {
  const note = $('continue-note').value.trim();
  if (!currentRunId || !note) {
    $('status').textContent = '이전 결과와 추가 관찰을 입력하세요.';
    return;
  }
  $('continue-btn').disabled = true;
  $('result').hidden = false;
  $('status').textContent = '이어 분석 요청 중…';
  try {
    const parentId = currentRunId;
    const response = await fetch('/api/continue', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({run_id: parentId, note, model: $('model').value,
        think_mode: $('think-mode') ? $('think-mode').value : 'quick'})
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    $('continue-panel').hidden = true;
    startTracking(result.job_id, 'continue', parentId);
  } catch (e) {
    $('status').textContent = '이어 분석 시작 실패';
    $('answer').textContent = e.message;
    $('continue-btn').disabled = false;
  }
});

health();
loadHistory();
$('refresh-models-btn')?.addEventListener('click', health);

$('pause-btn')?.addEventListener('click', async () => {
  if (!activeJobId) return;
  try {
    await fetch('/api/pause', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({job_id: activeJobId})
    });
  } catch (e) {}
});

$('resume-btn')?.addEventListener('click', async () => {
  if (!activeJobId) return;
  try {
    await fetch('/api/resume', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({job_id: activeJobId})
    });
  } catch (e) {}
});

$('model')?.addEventListener('change', () => {
  const isOllama = !$('model').value.startsWith('gpt-');
  if ($('think-mode-container')) {
    $('think-mode-container').style.display = isOllama ? 'block' : 'none';
  }
});
