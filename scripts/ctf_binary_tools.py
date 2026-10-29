"""Bounded, non-executing inspection of uploaded challenge binaries."""
from __future__ import annotations

from pathlib import Path
import re


def _elf_file(path: Path):
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise RuntimeError("ELF 분석에는 pyelftools가 필요합니다. pip install -r requirements.txt를 실행하세요.") from exc
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
        names = {name for name, _, _ in all_symbols}
        canary = "referenced" if "__stack_chk_fail" in names else "not_observed"
        symbols = []
        seen = set()
        for name, address, size in sorted(all_symbols, key=lambda item: (item[1] == 0, item[1], item[0])):
            if name in seen or (symbol_filter and symbol_filter.casefold() not in name.casefold()):
                continue
            seen.add(name)
            symbols.append(f"{name}@0x{address:x} size={size}")
            if len(symbols) >= 80:
                break
        summary = (f"file={path.name}; class={elf.elfclass}; machine={elf['e_machine']}; "
                   f"type={elf['e_type']}; entry=0x{int(elf['e_entry']):x}; "
                   f"NX={nx}; RELRO={relro}; stack_canary_reference={canary}\n"
                   "Note: ET_DYN may be a PIE executable or a shared library; a canary reference does not prove every function is protected.\n"
                   f"function_symbols ({len(symbols)} shown):\n" + "\n".join(symbols))
        return summary[:9000]
    except Exception as exc:
        return f"ELF 검사 실패: {type(exc).__name__}: {exc}"
    finally:
        stream.close()


def disassemble_function(path: Path, symbol_name: str, max_instructions: int = 120) -> str:
    if not symbol_name or len(symbol_name) > 120:
        return "함수 심볼 이름은 1~120자여야 합니다."
    max_instructions = max(1, min(int(max_instructions), 200))
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_ARM
        from elftools.elf.sections import SymbolTableSection
        stream, elf = _elf_file(path)
    except Exception as exc:
        return f"디스어셈블러 준비 실패: {type(exc).__name__}: {exc}"
    try:
        machine = elf["e_machine"]
        if machine == "EM_X86_64":
            decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        elif machine == "EM_386":
            decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        elif machine == "EM_AARCH64":
            decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        else:
            return f"지원하지 않는 디스어셈블리 아키텍처: {machine}"
        symbol = None
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for candidate in section.iter_symbols():
                    if candidate.name == symbol_name and int(candidate["st_value"]) > 0:
                        symbol = candidate
                        break
            if symbol is not None:
                break
        if symbol is None:
            return f"함수 심볼을 찾지 못했습니다: {symbol_name}. inspect_elf로 심볼을 확인하세요."
        address = int(symbol["st_value"])
        segment = next((seg for seg in elf.iter_segments()
                        if seg["p_type"] == "PT_LOAD" and (seg["p_flags"] & 1)
                        and int(seg["p_vaddr"]) <= address < int(seg["p_vaddr"]) + int(seg["p_filesz"])), None)
        if segment is None:
            return f"실행 가능한 파일 구간에서 함수 주소 0x{address:x}를 찾지 못했습니다."
        offset = int(segment["p_offset"]) + address - int(segment["p_vaddr"])
        available = int(segment["p_filesz"]) - (address - int(segment["p_vaddr"]))
        size = int(symbol["st_size"]) or 512
        count = min(size, available, 4096)
        stream.seek(offset)
        code = stream.read(count)
        lines = [f"function={symbol_name}; address=0x{address:x}; symbol_size={int(symbol['st_size'])}; file_offset=0x{offset:x}"]
        for instruction in decoder.disasm(code, address, count=max_instructions):
            lines.append(f"0x{instruction.address:x}: {instruction.mnemonic} {instruction.op_str}".rstrip())
        if len(lines) == 1:
            return lines[0] + "\n명령어를 해석하지 못했습니다."
        return "\n".join(lines)[:12000]
    except Exception as exc:
        return f"함수 디스어셈블 실패: {type(exc).__name__}: {exc}"
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
