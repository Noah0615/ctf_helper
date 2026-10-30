const $ = id => document.getElementById(id);
let currentRunId = null;

const CATEGORY_HINTS = {
  auto: "문제 설명과 첨부 파일을 분석하여 최적의 분석 흐름을 자동으로 결정합니다.",
  web: "웹 소스(라우트, 템플릿, Dockerfile), 환경 변수, robots.txt 분석. 필요 시 http_get / http_post 도구로 서버 응답 확인.",
  pwn: "바이너리 아키텍처, 보호 기법(PIE, Canary, NX), 버퍼 및 포맷스트링 취약점 분석. (실행 불가, 정적 분석 전용)",
  reversing: "파일 매직, 엔트로피, 인쇄 가능 문자열(ASCII/UTF-16LE), 디스어셈블리 및 상수/인코딩 분석.",
  crypto: "암호 알고리즘(RSA, AES, XOR, PRNG), 취약한 키/파라미터 분석. decode_text 및 오프라인 Python 계산 활용.",
  forensics: "파일 시그니처, 메타데이터, 아카이브 구조(inspect_archive, read_archive_entry), 바이너리 문자열 검사.",
  "ai-security": "프롬프트 템플릿, 탈옥(Jailbreak) 패턴, 시스템 프롬프트 누출, 모델 가중치/설정 파일 분석.",
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

// File list badges & Drag-and-drop
function updateFileList() {
  const listEl = $('file-list');
  listEl.replaceChildren();
  const files = $('files').files;
  if (!files || !files.length) return;
  for (const f of files) {
    const badge = document.createElement('span');
    badge.className = 'file-badge';
    const size = f.size >= 1024 * 1024
      ? `${(f.size / (1024 * 1024)).toFixed(2)} MiB`
      : `${(f.size / 1024).toFixed(1)} KiB`;
    badge.textContent = `${f.name} (${size})`;
    listEl.append(badge);
  }
}
$('files').addEventListener('change', updateFileList);

const dropZone = $('drop-zone');
['dragenter', 'dragover'].forEach(name => {
  dropZone.addEventListener(name, e => { e.preventDefault(); dropZone.classList.add('dragover'); });
});
['dragleave', 'drop'].forEach(name => {
  dropZone.addEventListener(name, e => { e.preventDefault(); dropZone.classList.remove('dragover'); });
});
dropZone.addEventListener('drop', e => {
  if (e.dataTransfer && e.dataTransfer.files.length) {
    $('files').files = e.dataTransfer.files;
    updateFileList();
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
  $('form').reset();
  endpointAutoFilled = false;
  $('cat-hint').textContent = CATEGORY_HINTS.auto;
  $('file-list').replaceChildren();
  $('result').hidden = true;
  $('status').textContent = '';
  $('flags').replaceChildren();
  $('answer').textContent = '';
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

async function loadHistory() {
  try {
    const list = await (await fetch('/api/history')).json();
    const sel = $('history-select');
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
  } catch (e) {
    // Ignore history errors
  }
}

$('history-select').addEventListener('change', () => {
  const id = $('history-select').value;
  if (!id) return;
  $('result').hidden = false;
  $('status').textContent = '저장된 분석 기록 불러오는 중…';
  $('flags').replaceChildren();
  $('answer').textContent = '';
  poll(id);
});

async function health() {
  try {
    const r = await (await fetch('/api/health')).json();
    const ollamaEl = $('health-ollama');
    const openaiEl = $('health-openai');
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

async function poll(id) {
  const r = await (await fetch(`/api/job/${encodeURIComponent(id)}`)).json();
  const items = r.result?.flag_candidates || [];
  const observations = r.result?.flag_observations || [];
  const remote = items.filter(item => item.source.startsWith('문제 웹 응답:') || item.source.startsWith('문제 서버:'));
  const remoteValues = new Set(remote.map(item => item.flag));
  const others = items.filter(item => !remoteValues.has(item.flag));
  $('status').textContent = r.status === 'done'
    ? (remote.length ? '분석 완료 · 문제 서버에서 후보 문자열 관찰'
       : others.length ? '분석 완료 · 미검증 후보 발견' : '분석 완료 · 정확한 flag 미확인')
    : `상태: ${r.status}`;
  $('events').textContent = (r.events || []).join('\n');
  if (r.status === 'done') {
    $('flags').replaceChildren();
    function addGroup(title, group) {
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
      flagSpan.className = 'flag-text';
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
    addGroup('조각 · 변환 또는 결합 필요', observations.filter(item => item.role === 'fragment'));
    addGroup('미끼로 표시된 문자열', observations.filter(item => item.role === 'decoy'));
    if (!observations.length && !items.length) $('flags').textContent = '관찰된 flag 형식 문자열이 없습니다. 문제 주소와 첨부 파일을 확인하세요.';

    if (r.result.cost_usd !== undefined) {
      $('cost').hidden = false;
      $('cost').textContent = `모델: ${r.result.model} · 과금: $${r.result.cost_usd.toFixed(4)} USD`;
    } else {
      $('cost').hidden = false;
      $('cost').textContent = `모델: ${r.result.model} (로컬 실행)`;
    }

    $('answer').textContent = r.result.answer + `\n\n실행 ID: ${r.result.run_id}`;
    if (r.result.parent_id) $('answer').textContent += `\n이전 실행 ID: ${r.result.parent_id}`;
    $('request-log').textContent = (r.result.requests || []).map(entry =>
      `${entry.at} ${entry.method} ${entry.path}\n${entry.request_body_preview || ''}\n${entry.response}`).join('\n\n') || '이 실행에서 기록된 요청이 없습니다.';
    currentRunId = r.result.run_id;
    $('continue-panel').hidden = false;
    $('continue-btn').disabled = false;
    $('submit').disabled = false;
    health();
    loadHistory();
  } else if (r.status === 'failed') {
    $('answer').textContent = `분석 실패: ${r.error}`;
    $('submit').disabled = false;
  } else {
    setTimeout(() => poll(id), 1500);
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
  try {
    const picked = [...$('files').files];
    if (picked.length > 20 || picked.some(file => file.size > 8 * 1024 * 1024) ||
        picked.reduce((sum, file) => sum + file.size, 0) > 12 * 1024 * 1024)
      throw new Error('파일은 최대 20개, 파일당 8 MiB, 합계 12 MiB까지 허용됩니다.');
    const files = await Promise.all(picked.map(file => new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve({name: file.name, data: String(reader.result).split(',')[1]});
      reader.onerror = () => reject(reader.error);
      reader.readAsDataURL(file);
    })));
    if ($('code').value.trim()) {
      if (files.some(file => file.name.toLowerCase() === 'pasted_code.txt'))
        throw new Error('pasted_code.txt 파일 이름이 붙여넣은 코드와 중복됩니다.');
      const bytes = new TextEncoder().encode($('code').value);
      if (bytes.length > 8 * 1024 * 1024) throw new Error('붙여넣은 코드가 8 MiB를 초과했습니다.');
      if (picked.length + 1 > 20 ||
          picked.reduce((sum, file) => sum + file.size, bytes.length) > 12 * 1024 * 1024)
        throw new Error('첨부 파일과 붙여넣은 코드는 합계 20개, 12 MiB를 초과할 수 없습니다.');
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
    poll(result.job_id);
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
  $('status').textContent = '이전 분석 기록을 불러오는 중…';
  try {
    const response = await fetch('/api/continue', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({run_id: currentRunId, note, model: $('model').value})
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    $('continue-note').value = '';
    $('continue-panel').hidden = true;
    $('events').textContent = '';
    poll(result.job_id);
  } catch (e) {
    $('status').textContent = '이어 분석 시작 실패';
    $('answer').textContent = e.message;
    $('continue-btn').disabled = false;
  }
});

health();
loadHistory();
