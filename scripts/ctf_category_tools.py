"""CTF Helper v2.1 - Specialized Category Tools (Crypto, Forensics, Web)."""
from __future__ import annotations

import difflib
import math
from pathlib import Path
import re
import struct


# =====================================================================
# 1. Cryptography: Parameter Extraction and Attack Analysis
# =====================================================================

def extract_crypto_params(content: str) -> str:
    """
    Extracts common crypto parameters (RSA n, e, c, p, q, d, etc.) from text,
    detects Byte-Caesar/1-byte shift and XOR ciphers on hex ciphertext,
    diagnoses vulnerabilities, and outputs ready-to-execute Python templates.
    """
    FLAG_PATTERN = re.compile(r"(?:ACDC|FLAG|CTF|DH|APS)\{[^}\r\n]{3,120}\}", re.IGNORECASE)

    # 1. Byte-Caesar / 1-byte shift and XOR cipher detection on hex strings
    hex_candidates = re.findall(r"[0-9a-fA-F]{16,}", content)
    for hc in hex_candidates:
        if len(hc) % 2 != 0:
            hc = hc[:-1]
        try:
            data = bytes.fromhex(hc)
        except Exception:
            continue

        # Test Byte-Caesar shift: c = (p + k) % 256 => p = (c - k) % 256
        for k in range(1, 256):
            dec = bytes((b - k) % 256 for b in data)
            try:
                dec_str = dec.decode("latin-1")
            except Exception:
                continue
            m = FLAG_PATTERN.search(dec_str)
            if m:
                flag = m.group(0)
                return (
                    f"[Byte-Caesar / 1-바이트 시프트 암호 자동 해독 성공!]\n"
                    f"- 발견된 암호화 키: key = {k} (0x{k:02x})\n"
                    f"- 복호화된 Flag: {flag}\n"
                    f"- 복호화된 평문 미리보기:\n"
                    f"  {dec_str[:220]}...\n\n"
                    f"[즉시 실행 가능한 공격 스크립트 (run_python용)]:\n"
                    f"```python\n"
                    f'enc = bytes.fromhex("{hc[:64]}") # 전체 암호문 길이: {len(data)}바이트\n'
                    f"key = {k}\n"
                    f"print(bytes((b - key) % 256 for b in enc).decode('latin1', errors='replace'))\n"
                    f"```"
                )

        # Test Single-byte XOR: c = p ^ k => p = c ^ k
        for k in range(1, 256):
            dec = bytes(b ^ k for b in data)
            try:
                dec_str = dec.decode("latin-1")
            except Exception:
                continue
            m = FLAG_PATTERN.search(dec_str)
            if m:
                flag = m.group(0)
                return (
                    f"[Single-byte XOR 암호 자동 해독 성공!]\n"
                    f"- 발견된 XOR 키: key = 0x{k:02x} ({k})\n"
                    f"- 복호화된 Flag: {flag}\n"
                    f"- 복호화된 평문 미리보기:\n"
                    f"  {dec_str[:220]}...\n\n"
                    f"[즉시 실행 가능한 공격 스크립트 (run_python용)]:\n"
                    f"```python\n"
                    f'enc = bytes.fromhex("{hc[:64]}") # 전체 암호문 길이: {len(data)}바이트\n'
                    f"key = {k}\n"
                    f"print(bytes(b ^ key for b in enc).decode('latin1', errors='replace'))\n"
                    f"```"
                )

    # 2. RSA / Discrete Log parameters extraction
    params = {}
    patterns = [
        (r"\b(?:n|N|modulus)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", "n"),
        (r"\b(?:e|E|exponent)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", "e"),
        (r"\b(?:c|C|ciphertext|ct|enc)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", "c"),
        (r"\b(?:p|P)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", "p"),
        (r"\b(?:q|Q)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", "q"),
        (r"\b(?:d|D|privkey)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", "d"),
        (r"\b(?:phi|Phi)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", "phi"),
    ]

    for pat, name in patterns:
        m = re.search(pat, content)
        if m:
            val_str = m.group(1)
            val = int(val_str, 16) if val_str.startswith("0x") or val_str.startswith("0X") else int(val_str)
            params[name] = val

    if not params:
        return "암호화 파라미터(n, e, c, p, q 등) 및 시프트/XOR 암호문을 감지하지 못했습니다."

    lines = ["[추출된 암호 파라미터]:"]
    for k, v in params.items():
        bit_len = v.bit_length()
        lines.append(f"  {k} = {v} ({bit_len} bits)")

    # Diagnosis & Recommended Attack
    lines.append("\n[취약점 진단 및 권장 공격법]:")
    e_val = params.get("e")
    n_val = params.get("n")
    c_val = params.get("c")
    p_val = params.get("p")
    q_val = params.get("q")

    attack_script = ""

    if p_val and q_val and e_val and c_val:
        lines.append("- p, q 소인수가 모두 노출되어 있습니다 -> d = pow(e, -1, (p-1)*(q-1)) 즉시 복호화 가능")
        attack_script = f"""# Directly decrypt with known p, q
p = {p_val}
q = {q_val}
e = {e_val}
c = {c_val}
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, p * q)
print('Decrypted bytes:', bytes.fromhex(hex(m)[2:]).decode('latin1', errors='replace'))
"""
    elif e_val == 3 and n_val and c_val:
        lines.append("- e = 3 (초저지수): m^3 < n 일 경우 세제곱근(cube root) 즉시 복호화 가능")
        attack_script = f"""# Low exponent e=3 cube root attack
import decimal
decimal.getcontext().prec = 1000
c = {c_val}
n = {n_val}
root = int(round(c ** (1/3)))
if pow(root, 3) == c:
    print('Found exact root!')
    print(bytes.fromhex(hex(root)[2:]).decode('latin1', errors='replace'))
else:
    # Try small k where m^3 = c + k*n
    for k in range(1, 100000):
        val = c + k * n
        r = int(decimal.Decimal(val) ** (decimal.Decimal(1)/3))
        if pow(r, 3) == val:
            print('Found with k =', k)
            print(bytes.fromhex(hex(r)[2:]).decode('latin1', errors='replace'))
            break
"""
    elif e_val and e_val > 65537 and n_val and c_val:
        lines.append("- e 값이 매우 큼: 작은 비밀키 d를 사용하는 Wiener's Attack 대상일 가능성 높음")
        attack_script = f"""# Wiener's attack (small d)
import owiener
n = {n_val}
e = {e_val}
c = {c_val}
d = owiener.attack(e, n)
if d:
    m = pow(c, d, n)
    print('Decrypted:', bytes.fromhex(hex(m)[2:]).decode('latin1', errors='replace'))
"""
    elif n_val and n_val.bit_length() <= 256:
        lines.append(f"- n 비트 수가 {n_val.bit_length()} bits로 매우 작습니다 -> Pollard rho 또는 페르마 소인수분해 가능")
        attack_script = f"""# Small modulus factorization
import math
n = {n_val}
e = {e_val or 65537}
c = {c_val}
# Fermat factorization
a = math.isqrt(n) + 1
while True:
    b2 = a*a - n
    if b2 >= 0:
        b = math.isqrt(b2)
        if b*b == b2:
            p = a - b
            q = a + b
            break
    a += 1
d = pow(e, -1, (p-1)*(q-1))
m = pow(c, d, n)
print('Decrypted:', bytes.fromhex(hex(m)[2:]).decode('latin1', errors='replace'))
"""

    if attack_script:
        lines.append("\n[즉시 실행 가능한 공격 스크립트 (run_python으로 실행 가능)]:\n```python\n" + attack_script + "```")

    return "\n".join(lines)


# =====================================================================
# 2. Forensics: File Carving and Magic Byte Overlay Scanner
# =====================================================================

SIGNATURES = [
    (b"PK\x03\x04", "ZIP Archive", b"PK\x05\x06", 22),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", b"IEND\xaeB\x60\x82", 8),
    (b"\xff\xd8\xff", "JPEG Image", b"\xff\xd9", 2),
    (b"\x7fELF", "ELF Binary", None, 0),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", None, 0),
    (b"\x1f\x8b", "GZIP Compressed", None, 0),
    (b"%PDF-", "PDF Document", b"%%EOF", 5),
    (b"Rar!\x1a\x07", "RAR Archive", None, 0),
]


def carve_file_signatures(path: Path) -> str:
    """
    Scans a file for embedded file formats, hidden ZIP/ELF overlays,
    and detects steganographic appended data after EOF.
    """
    if not path.is_file():
        return f"파일을 찾을 수 없습니다: {path}"
    data = path.read_bytes()
    file_size = len(data)
    findings = []

    for magic, name, trailer, trailer_extra in SIGNATURES:
        start_pos = 0
        while True:
            idx = data.find(magic, start_pos)
            if idx == -1:
                break
            end_info = ""
            if trailer:
                t_idx = data.find(trailer, idx)
                if t_idx != -1:
                    end_offset = t_idx + trailer_extra
                    length = end_offset - idx
                    end_info = f"~ 0x{end_offset:x} (길이: {length} bytes)"
                    if idx == 0 and end_offset < file_size:
                        overlay_size = file_size - end_offset
                        findings.append(
                            f"[오버레이 데이터 감지] 0x{end_offset:x} 부터 파일 끝까지 {overlay_size} bytes의 은닉/추가 데이터 존재 (Steganography 의심!)"
                        )
            findings.append(f"0x{idx:x}: {name} {end_info}")
            start_pos = idx + len(magic)

    if not findings:
        return f"파일 크기: {file_size} bytes. 알려진 시그니처가 발견되지 않았습니다."

    return (
        f"[파일 시그니처 및 카빙 분석: {path.name} ({file_size} bytes)]\n"
        + "\n".join(f"- {f}" for f in findings)
    )


# =====================================================================
# 3. Forensics: PCAP / Packet Capture Analysis
# =====================================================================

def inspect_pcap(path: Path) -> str:
    """
    Analyzes .pcap or .pcapng files using pure Python.
    Extracts packet counts, IP addresses, HTTP GET/POST methods, and plaintext flags.
    """
    if not path.is_file():
        return f"PCAP 파일을 찾을 수 없습니다: {path}"

    data = path.read_bytes()
    if not (data.startswith(b"\xd4\xc3\xb2\xa1") or data.startswith(b"\xa1\xb2\xc3\xd4") or
            data.startswith(b"\x0a\x0d\x0d\x0a")):
        return "유효한 PCAP 또는 PCAPNG 파일 매직 넘버가 아닙니다."

    # Scan for HTTP methods and URIs
    http_requests = []
    for m in re.finditer(rb"(GET|POST|PUT|DELETE)\s+([^\s\r\n]+)\s+HTTP/1\.[01]", data):
        method = m.group(1).decode("ascii", errors="replace")
        uri = m.group(2).decode("ascii", errors="replace")
        http_requests.append(f"{method} {uri}")

    # Scan for DNS queries
    dns_queries = []
    for m in re.finditer(rb"\x00\x01\x00\x01[\x00-\xff]{0,4}([a-zA-Z0-9_-]{2,30}\.[a-zA-Z]{2,10})", data):
        dns_queries.append(m.group(1).decode("ascii", errors="replace"))

    # Scan for candidate flag strings directly inside packets
    flag_matches = []
    for m in re.finditer(rb"(?:DH|FLAG|CTF|ACDC)\{[^}\r\n]{1,100}\}", data):
        flag_matches.append(m.group().decode("ascii", errors="replace"))

    lines = [f"[PCAP 패킷 캡처 분석: {path.name} ({len(data)} bytes)]"]
    if flag_matches:
        unique_flags = list(dict.fromkeys(flag_matches))
        lines.append(f"- 패킷 페이로드에서 직접 발견된 플래그:\n  " + "\n  ".join(unique_flags))

    if http_requests:
        lines.append(f"\n[추출된 HTTP 요청 (총 {len(http_requests)}건)]:")
        for req in list(dict.fromkeys(http_requests))[:20]:
            lines.append(f"  - {req}")

    if dns_queries:
        lines.append(f"\n[추출된 DNS 쿼리]:")
        for q in list(dict.fromkeys(dns_queries))[:10]:
            lines.append(f"  - {q}")

    return "\n".join(lines)


# =====================================================================
# 4. Web: HTTP Response Difference Comparison (for Blind SQLi / Oracles)
# =====================================================================

def diff_http_responses(body1: str, body2: str, label1: str = "요청 1", label2: str = "요청 2") -> str:
    """
    Compares two HTTP response bodies and highlights differences (lengths, keywords, lines).
    Essential for identifying blind boolean-based SQL injection markers or prefix oracle differences.
    """
    len1, len2 = len(body1), len(body2)
    diff_lines = list(difflib.unified_diff(
        body1.splitlines(),
        body2.splitlines(),
        fromfile=label1,
        tofile=label2,
        lineterm=""
    ))

    summary = [
        f"[HTTP 응답 차이 분석]:",
        f"- {label1} 본문 길이: {len1} bytes",
        f"- {label2} 본문 길이: {len2} bytes (길이 차이: {abs(len1 - len2)} bytes)",
    ]

    if len1 == len2 and body1 == body2:
        summary.append("- 두 응답의 내용이 완전히 동일합니다 (차이 없음).")
        return "\n".join(summary)

    summary.append("- 변경된 핵심 내용 (Diff):")
    meaningful_diff = [line for line in diff_lines if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))]
    summary.extend("  " + l for l in meaningful_diff[:25])
    return "\n".join(summary)
