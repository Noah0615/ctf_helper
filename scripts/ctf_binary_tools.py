"""Bounded, non-executing inspection of uploaded challenge binaries."""
from __future__ import annotations

from pathlib import Path
import re


def _elf_file(path: Path):
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise RuntimeError("ELF 분석에는 pyelftools가 필요합니다. requirements-ctf-helper.txt를 설치하세요.") from exc
    stream = path.open("rb")
    try:
        return stream, ELFFile(stream)
    except Exception:
        stream.close()
        raise


def inspect_elf(path: Path, symbol_filter: str = "") -> str:
    if len(symbol_filter) > 100:
        return "심볼 검색어는 100자 이하로 입력하세요."
    try:
        stream, elf = _elf_file(path)
    except Exception as exc:
        return f"ELF 열기 실패: {type(exc).__name__}: {exc}"
    try:
        from elftools.elf.sections import SymbolTableSection
        from elftools.elf.dynamic import DynamicSection
        segments = list(elf.iter_segments())
        stack = next((seg for seg in segments if seg["p_type"] == "PT_GNU_STACK"), None)
        nx = "unknown" if stack is None else "enabled" if not (stack["p_flags"] & 1) else "disabled"
        relro_segment = any(seg["p_type"] == "PT_GNU_RELRO" for seg in segments)
        bind_now = False
        all_symbols = []
        for section in elf.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_BIND_NOW":
                        bind_now = True
                    elif tag.entry.d_tag == "DT_FLAGS" and int(tag.entry.d_val) & 0x8:
                        bind_now = True
                    elif tag.entry.d_tag == "DT_FLAGS_1" and int(tag.entry.d_val) & 0x1:
                        bind_now = True
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol.name and symbol["st_info"]["type"] == "STT_FUNC":
                        all_symbols.append((symbol.name, int(symbol["st_value"]), int(symbol["st_size"])))
        relro = "full" if relro_segment and bind_now else "partial" if relro_segment else "none"
        pie = elf.header["e_type"] == "ET_DYN"
        canary = any("__stack_chk_fail" in name for name, _, _ in all_symbols)
        lines = [
            f"file={path.name}; arch={elf.get_machine_arch()}; bits={elf.elfclass}; endian={elf.little_endian and 'little' or 'big'}",
            f"entry_point=0x{elf.header['e_entry']:x}; pie={pie}; nx={nx}; relro={relro}; stack_canary_symbol={canary}",
        ]
        needle = symbol_filter.casefold()
        filtered = [s for s in all_symbols if not needle or needle in s[0].casefold()]
        filtered.sort(key=lambda s: s[1])
        lines.append(f"functions_found={len(filtered)} (total_named={len(all_symbols)})")
        for name, value, size in filtered[:60]:
            lines.append(f"  0x{value:x} [{size}B] {name}")
        return "\n".join(lines)[:8000]
    finally:
        stream.close()


def _capstone_decoder(elf):
    try:
        import capstone
    except ImportError as exc:
        raise RuntimeError("디스어셈블리에는 capstone이 필요합니다. requirements-ctf-helper.txt를 설치하세요.") from exc
    arch = elf.get_machine_arch().lower()
    if "x86" in arch or "amd64" in arch or "x64" in arch or "i386" in arch or "i686" in arch:
        mode = capstone.CS_MODE_64 if elf.elfclass == 64 else capstone.CS_MODE_32
        return capstone.Cs(capstone.CS_ARCH_X86, mode)
    if ("arm" in arch or "aarch64" in arch) and elf.elfclass == 64:
        return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    if "arm" in arch:
        return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    raise ValueError(f"지원되지 않는 아키텍처: {elf.get_machine_arch()}")


def disassemble_function(path: Path, symbol_name: str, max_instructions: int = 120) -> str:
    if not symbol_name or len(symbol_name) > 80:
        return "함수 심볼 이름은 1~80자여야 합니다."
    max_instructions = max(1, min(int(max_instructions), 300))
    try:
        stream, elf = _elf_file(path)
    except Exception as exc:
        return f"ELF 열기 실패: {type(exc).__name__}: {exc}"
    try:
        from elftools.elf.sections import SymbolTableSection
        decoder = _capstone_decoder(elf)
        target = None
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol.name == symbol_name and symbol["st_info"]["type"] == "STT_FUNC":
                        target = symbol
                        break
                if target:
                    break
        if target is None:
            return f"함수 심볼을 찾지 못했습니다: {symbol_name}. inspect_elf 로 심볼 목록을 확인하세요."
        address = int(target["st_value"])
        text_section = None
        for section in elf.iter_sections():
            start = int(section["sh_addr"])
            end = start + int(section["sh_size"])
            if start <= address < end:
                text_section = section
                break
        if text_section is None:
            return f"함수 주소 0x{address:x} 가 속한 섹션을 찾을 수 없습니다."
        offset = int(text_section["sh_offset"]) + (address - int(text_section["sh_addr"]))
        count = max(int(target["st_size"]), 32)
        count = min(count, 4096)
        stream.seek(offset)
        code = stream.read(count)
        lines = [f"function={symbol_name}; address=0x{address:x}; symbol_size={int(target['st_size'])}; file_offset=0x{offset:x}"]
        for instruction in decoder.disasm(code, address, count=max_instructions):
            lines.append(f"0x{instruction.address:x}: {instruction.mnemonic} {instruction.op_str}".rstrip())
        if len(lines) == 1:
            return lines[0] + "\n명령어를 해석하지 못했습니다."
        return "\n".join(lines)[:12000]
    except Exception as exc:
        return f"함수 디스어셈블 실패: {type(exc).__name__}: {exc}"
    finally:
        stream.close()


def calculate_stack_layout(path: Path, symbol_name: str = "main") -> str:
    """
    Parses function assembly to compute exact stack buffer offsets,
    canary locations, and distance to saved return address (RIP).
    Eliminates mental arithmetic errors for 8B models.
    """
    try:
        stream, elf = _elf_file(path)
    except Exception as exc:
        return f"ELF 열기 실패: {type(exc).__name__}: {exc}"
    try:
        from elftools.elf.sections import SymbolTableSection
        decoder = _capstone_decoder(elf)
        target = None
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol.name == symbol_name and symbol["st_info"]["type"] == "STT_FUNC":
                        target = symbol
                        break
                if target:
                    break
        if target is None:
            return f"함수 '{symbol_name}' 심볼을 찾을 수 없습니다."

        address = int(target["st_value"])
        for section in elf.iter_sections():
            start = int(section["sh_addr"])
            end = start + int(section["sh_size"])
            if start <= address < end:
                offset = int(section["sh_offset"]) + (address - start)
                break
        else:
            return f"함수 '{symbol_name}' 섹션을 찾을 수 없습니다."

        stream.seek(offset)
        code = stream.read(min(int(target["st_size"]) or 512, 1024))
        insns = list(decoder.disasm(code, address, count=80))

        stack_alloc = 0
        canary_offset = None
        buffer_rbp_offset = None
        input_call = None

        for insn in insns:
            # Detect sub rsp, X
            if insn.mnemonic == "sub" and "rsp" in insn.op_str:
                m = re.search(r"0x[0-9a-fA-F]+|\d+", insn.op_str)
                if m:
                    stack_alloc = int(m.group(0), 16 if "0x" in m.group(0) else 10)
            # Detect canary setup (fs:[0x28] into [rbp - X])
            if "fs:[0x28]" in insn.op_str:
                canary_offset = 8
            # Detect lea rax, [rbp - X]
            if insn.mnemonic == "lea" and "rbp -" in insn.op_str:
                m = re.search(r"rbp\s*-\s*(0x[0-9a-fA-F]+|\d+)", insn.op_str)
                if m:
                    offset_val = int(m.group(1), 16 if "0x" in m.group(1) else 10)
                    if buffer_rbp_offset is None or offset_val > buffer_rbp_offset:
                        buffer_rbp_offset = offset_val
            # Detect input function call
            if insn.mnemonic == "call" and any(fn in insn.op_str for fn in ("read", "gets", "scanf", "fgets", "__isoc99_scanf")):
                input_call = insn.op_str

        bits = elf.elfclass
        ptr_size = 8 if bits == 64 else 4
        ret_reg = "RIP" if bits == 64 else "EIP"

        lines = [f"[스택 레이아웃 정밀 분석: '{symbol_name}' ({bits}-bit)]"]
        if stack_alloc:
            lines.append(f"- 스택 프레임 할당량: 0x{stack_alloc:x} ({stack_alloc} bytes)")
        if canary_offset:
            lines.append(f"- 카나리(Stack Canary) 탐지됨: [rbp - 0x8]")
        if buffer_rbp_offset is not None:
            dist_to_rbp = buffer_rbp_offset
            dist_to_ret = buffer_rbp_offset + ptr_size
            lines.append(f"- 입력 버퍼 위치: [rbp - 0x{buffer_rbp_offset:x}] (RBP 기준 아래로 {buffer_rbp_offset} bytes)")
            if input_call:
                lines.append(f"- 호출된 입력 함수: {input_call}")
            lines.append(f"- Saved RBP까지의 거리: {dist_to_rbp} bytes")
            lines.append(f"★ Saved {ret_reg} (리턴 주소)까지의 거리: {dist_to_ret} bytes (0x{dist_to_ret:x})")
            lines.append(f"- 권장 익스플로잇 페이로드 형태:")
            lines.append(f"  payload = b'A' * {dist_to_ret} + p64(target_address)")
        else:
            lines.append("- 단일 버퍼 오프셋을 특정하지 못했습니다. disassemble_function 으로 전체 흐름을 확인하세요.")

        return "\n".join(lines)
    finally:
        stream.close()


def find_rop_gadgets(path: Path, max_gadgets: int = 25) -> str:
    """
    Scans executable sections of an ELF for high-value ROP gadgets.
    """
    try:
        stream, elf = _elf_file(path)
    except Exception as exc:
        return f"ELF 열기 실패: {type(exc).__name__}: {exc}"
    try:
        decoder = _capstone_decoder(elf)
        executable_data = []
        for section in elf.iter_sections():
            if section["sh_flags"] & 4:  # SHF_EXECINSTR
                addr = int(section["sh_addr"])
                stream.seek(int(section["sh_offset"]))
                data = stream.read(int(section["sh_size"]))
                executable_data.append((addr, data))

        GADGET_PATTERNS = [
            (b"\x5f\xc3", "pop rdi; ret"),
            (b"\x5e\xc3", "pop rsi; ret"),
            (b"\x5a\xc3", "pop rdx; ret"),
            (b"\x58\xc3", "pop rax; ret"),
            (b"\xc3", "ret"),
            (b"\x0f\x05", "syscall"),
            (b"\xc9\xc3", "leave; ret"),
        ]

        gadgets = []
        for base_addr, data in executable_data:
            for pattern, name in GADGET_PATTERNS:
                idx = 0
                while True:
                    idx = data.find(pattern, idx)
                    if idx == -1 or len(gadgets) >= max_gadgets:
                        break
                    gadget_addr = base_addr + idx
                    gadgets.append((gadget_addr, name))
                    idx += 1
            if len(gadgets) >= max_gadgets:
                break

        if not gadgets:
            return "유용한 ROP 가젯을 발견하지 못했습니다."

        gadgets.sort(key=lambda g: g[0])
        lines = [f"[발견된 핵심 ROP 가젯 목록 (최대 {max_gadgets}개)]"]
        for addr, name in gadgets:
            lines.append(f"  0x{addr:x}: {name}")
        return "\n".join(lines)
    finally:
        stream.close()


def find_string_xrefs(path: Path, term: str) -> str:
    """
    Finds cross-references to a string inside an ELF binary,
    identifying the exact function and instruction that uses it.
    """
    if not term or len(term) > 100:
        return "검색어는 1~100자여야 합니다."
    try:
        stream, elf = _elf_file(path)
    except Exception as exc:
        return f"ELF 열기 실패: {type(exc).__name__}: {exc}"
    try:
        from elftools.elf.sections import SymbolTableSection
        # 1. Find string in binary
        data = path.read_bytes()
        needle = term.encode("utf-8")
        idx = data.find(needle)
        if idx == -1:
            return f"바이너리 내에서 문자열 '{term}'을 찾을 수 없습니다."

        # Find virtual address of string
        str_vaddr = None
        for section in elf.iter_sections():
            start = int(section["sh_offset"])
            end = start + int(section["sh_size"])
            if start <= idx < end:
                str_vaddr = int(section["sh_addr"]) + (idx - start)
                break

        if str_vaddr is None:
            return f"문자열 오프셋 0x{idx:x}의 가상 주소를 찾을 수 없습니다."

        decoder = _capstone_decoder(elf)
        functions = []
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol["st_info"]["type"] == "STT_FUNC" and symbol.name:
                        functions.append((symbol.name, int(symbol["st_value"]), int(symbol["st_size"])))

        xrefs = []
        for section in elf.iter_sections():
            if section["sh_flags"] & 4:  # SHF_EXECINSTR
                base = int(section["sh_addr"])
                stream.seek(int(section["sh_offset"]))
                code = stream.read(int(section["sh_size"]))
                for insn in decoder.disasm(code, base):
                    # Check RIP-relative or direct address
                    target_addr = None
                    if "rip" in insn.op_str:
                        m = re.search(r"0x[0-9a-fA-F]+", insn.op_str)
                        if m:
                            disp = int(m.group(0), 16)
                            target_addr = insn.address + insn.size + (disp if disp < 0x80000000 else disp - 0x100000000)
                    elif f"0x{str_vaddr:x}" in insn.op_str:
                        target_addr = str_vaddr

                    if target_addr == str_vaddr:
                        fn_name = "unknown"
                        for name, f_start, f_size in functions:
                            if f_start <= insn.address < f_start + max(f_size, 16):
                                fn_name = name
                                break
                        xrefs.append((insn.address, fn_name, f"{insn.mnemonic} {insn.op_str}"))

        if not xrefs:
            return f"문자열 '{term}' (주소: 0x{str_vaddr:x})을 참조하는 코드를 찾지 못했습니다."

        lines = [f"[문자열 '{term}' (가상 주소: 0x{str_vaddr:x}) 참조 역추적 결과]"]
        for addr, fn, code_str in xrefs:
            lines.append(f"- 함수 '{fn}' 내부 (0x{addr:x}): {code_str}")
        return "\n".join(lines)
    finally:
        stream.close()


def search_binary_strings(path: Path, term: str) -> str:
    if not term or len(term) > 100:
        return "검색어는 1~100자여야 합니다."
    data = path.read_bytes()
    needle = term.casefold()
    matches = []
    for item in re.finditer(rb"[ -~]{4,240}", data):
        decoded = item.group().decode("ascii")
        if needle in decoded.casefold():
            matches.append((item.start(), "ASCII", decoded))
            if len(matches) >= 40:
                break
    if len(matches) < 40:
        for item in re.finditer(rb"(?:[\x20-\x7e]\x00){4,120}", data):
            decoded = item.group().decode("utf-16le")
            if needle in decoded.casefold():
                matches.append((item.start(), "UTF-16LE", decoded))
                if len(matches) >= 40:
                    break
    matches.sort(key=lambda item: item[0])
    return "\n".join(f"0x{offset:x} [{kind}] {value}" for offset, kind, value in matches)[:9000] or "일치 문자열 없음"


def file_hexdump(path: Path, offset: int = 0, length: int = 256) -> str:
    size = path.stat().st_size
    if offset < 0 or offset >= size:
        return f"오프셋은 0 이상 {max(0, size - 1)} 이하여야 합니다."
    length = max(1, min(int(length), 512))
    with path.open("rb") as stream:
        stream.seek(offset)
        raw = stream.read(length)
    lines = [f"file={path.name}; offset=0x{offset:x}; bytes={len(raw)}"]
    for pos in range(0, len(raw), 16):
        chunk = raw[pos:pos + 16]
        printable = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset + pos:08x}  {chunk.hex(' '):47}  {printable}")
    return "\n".join(lines)
