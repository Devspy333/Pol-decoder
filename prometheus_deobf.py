#!/usr/bin/env python3
import re
import sys
import os
import argparse

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

VERSION = "2.1.2"

def log(message, level="info"):
    if HAS_COLOR:
        colors = {"debug": Fore.CYAN, "info": Fore.GREEN, "warning": Fore.YELLOW, "error": Fore.RED}
        print(f"[{colors.get(level, '')}{level.upper()}{Style.RESET_ALL}] {message}")
    else:
        print(f"[{level.upper()}] {message}")

class PrometheusDecryptor:
    def __init__(self):
        self.lcg_mul = 1103515245
        self.lcg_add = 12345
        self.lcg_mod = 2**45
        self.xor_mul = 257
        self.xor_mod = 65537

    def decrypt(self, data, seed):
        lcg = seed % self.lcg_mod
        xor = 1
        out = []
        for ch in data:
            lcg = (lcg * self.lcg_mul + self.lcg_add) % self.lcg_mod
            xor = (xor * self.xor_mul) % self.xor_mod
            if xor == 1:
                xor = (xor * self.xor_mul) % self.xor_mod
            key = (lcg + xor) & 0xFF
            out.append(chr(ord(ch) ^ key))
        return ''.join(out)

def find_and_decrypt_strings(code, verbose=False):
    decryptor = PrometheusDecryptor()
    patterns = [
        r'function\s+([a-zA-Z_][\w]*)\s*\(\s*([a-zA-Z_][\w]*)\s*\)\s*local\s+[a-zA-Z_][\w]*\s*=\s*(\d+)',
        r'local\s+([a-zA-Z_][\w]*)\s*=\s*function\s*\(\s*([a-zA-Z_][\w]*)\s*\)\s*local\s+[a-zA-Z_][\w]*\s*=\s*(\d+)',
        r'function\s+([a-zA-Z_][\w]*)\s*\(\s*([a-zA-Z_][\w]*)\s*\)\s*local\s+_\s*=\s*(\d+)',
        r'local\s+function\s+([a-zA-Z_][\w]*)\s*\(\s*([a-zA-Z_][\w]*)\s*\)\s*local\s+[a-zA-Z_][\w]*\s*=\s*(\d+)',
        r'function\s+([a-zA-Z_][\w]*)\s*\(\s*([a-zA-Z_][\w]*)\s*\)\s*local\s+[a-zA-Z_][\w]*\s*=\s*(\d+)[^\n]*bit32\.bxor',
    ]
    total_replaced = 0
    for pat_idx, pat in enumerate(patterns):
        matches = list(re.finditer(pat, code))
        if not matches:
            continue
        for m in matches:
            func_name = m.group(1)
            seed = int(m.group(3))
            if verbose:
                log(f"Found decryptor: {func_name} (seed={seed}) via pattern {pat_idx}", "debug")
            call_pat = rf'{func_name}\s*\(\s*"([^"]+)"\s*\)'
            new_code, n = re.subn(call_pat, lambda mm, s=seed: f'"{decryptor.decrypt(mm.group(1), s)}"', code)
            if n:
                code = new_code
                total_replaced += n
                if verbose:
                    log(f"Decrypted {n} strings using {func_name}", "debug")
        if total_replaced:
            break
    if verbose and total_replaced == 0:
        log("No string decryption pattern matched", "warning")
    return code

def resolve_constant_arrays(code, verbose=False):
    arrays = {}
    for m in re.finditer(r'local\s+([a-zA-Z_][\w]*)\s*=\s*{([^}]+)}', code, re.DOTALL):
        name, content = m.group(1), m.group(2)
        elems = []
        for part in re.split(r',\s*(?![^{]*})', content):
            part = part.strip()
            if part.startswith(('"', "'")):
                elems.append(part)
            elif part.isdigit() or (part.startswith('-') and part[1:].isdigit()):
                elems.append(part)
            elif part in ('true', 'false'):
                elems.append(part)
            else:
                elems.append('nil')
        arrays[name] = elems
        if verbose:
            log(f"Found constant array {name} with {len(elems)} elements", "debug")
    replaced = 0
    for name, elems in arrays.items():
        for i, val in enumerate(elems, 1):
            pat = rf'{re.escape(name)}\[\s*{i}\s*\]'
            # SAFE: use lambda to avoid backreference interpretation
            new_code, n = re.subn(pat, lambda m: val, code)
            if n:
                code = new_code
                replaced += n
        for m in re.finditer(rf'{re.escape(name)}\[\s*([a-zA-Z_][\w]*)\s*([+-])\s*(\d+)\s*\]', code):
            comment = f"-- TODO: resolve {name}[{m.group(1)}{m.group(2)}{m.group(3)}]"
            code = code.replace(m.group(0), comment)
            if verbose:
                log(f"Marked unresolved array access: {name}[{m.group(1)}{m.group(2)}{m.group(3)}]", "debug")
    if verbose and replaced:
        log(f"Resolved {replaced} constant array accesses", "debug")
    return code

def remove_antitamper(code, verbose=False):
    patterns = [
        (r'pcall\s*\([^)]*\)\s*', ''),
        (r'debug\.getinfo\s*\([^)]*\)\s*', ''),
        (r'debug\.sethook\s*\([^)]*\)\s*', ''),
        (r'local valid\s*=\s*true\s*;.*?if valid then else.*?end', 'local valid = true', re.DOTALL),
        (r'load\s*\(\s*[^)]*\s*\)\s*\(\)', ''),
        (r'getfenv\s*\(\s*\)\s*\([^)]*\)', ''),
        (r'setfenv\s*\(\s*[^,]+,\s*[^)]+\)', ''),
    ]
    removed = 0
    for pat, repl, *flags in patterns:
        fl = flags[0] if flags else 0
        new_code, n = re.subn(pat, repl, code, flags=fl)
        if n:
            code = new_code
            removed += n
    if verbose and removed:
        log(f"Removed {removed} anti-tamper patterns", "debug")
    return code

def simplify_control_flow(code, verbose=False):
    code, n1 = re.subn(r'else\s+if', 'elseif', code)
    code, n2 = re.subn(r'if\s+(\w+)\s+then\s+\1\s*=\s*\1\s+end', '', code)
    code = re.sub(r'(if\s+accumulator\s*<\s*)(-?\d+)', r'\1PHASE_\2', code)
    if verbose and (n1 or n2):
        log(f"Simplified control flow (elseif: {n1}, removed dead if: {n2})", "debug")
    return code

def remove_junk(code, verbose=False):
    patterns = [
        (r'local function \w+\(\)\s*return ""\s*end', ''),
        (r'if \w+ == -\d+ then \w+ = -\d+ end', ''),
        (r'for \w+ = -\d+,#\w+,-?\d+ do end', ''),
        (r'\w+ = \w+ [+-] \d+\s*$', '', re.MULTILINE),
        (r'local \w+ = nil\s*', ''),
        (r'\w+\s*=\s*\w+\s*[&|^<>]+\s*\w+', ''),
        (r'local \w+ = \w+ \[\s*\]', ''),
    ]
    removed = 0
    for pat, repl, *flags in patterns:
        fl = flags[0] if flags else 0
        new_code, n = re.subn(pat, repl, code, flags=fl)
        if n:
            code = new_code
            removed += n
    if verbose and removed:
        log(f"Removed {removed} junk code patterns", "debug")
    return code

def demangle_names(code, verbose=False):
    mapping = {
        'V': 'table', 'f': 'func', 'R': 'string', 'O': 'math', 'N': 'num',
        'X': 'char', 'G': 'table_insert', 'p': 'string_sub', 'i': 'concat',
        't': 'accumulator', 'K': 'bit32', 'D': 'buffer', 'S': 'state',
        'T': 'temp', 'Z': 'result', 'Y': 'io', 'Q': 'flag', 'P': 'position',
        'W': 'window', 'L': 'length', 'C': 'count', 'M': 'max', 'J': 'jump',
    }
    changes = 0
    for old, new in mapping.items():
        new_code, n = re.subn(rf'\b{old}\b(?![\'"])', new, code)
        if n:
            code = new_code
            changes += n
    if verbose and changes:
        log(f"Demangled {changes} variable names", "debug")
    return code

def reconstruct_string_concat(code, verbose=False):
    def repl(m):
        parts = re.findall(r'"([^"]+)"', m.group(1))
        return '"' + ''.join(parts) + '"' if parts else m.group(0)
    new_code, n = re.subn(r'table\.concat\(\{([^}]+)\}\)', repl, code)
    if n and verbose:
        log(f"Reconstructed {n} table.concat string fragments", "debug")
    return new_code

def detect_vm_dispatch_loops(code, verbose=False):
    pattern = r'while\s+true\s+do\s*((?:[^e]|e(?!nd))*?)end'
    loops = re.findall(pattern, code, re.DOTALL)
    if verbose and loops:
        log(f"Found {len(loops)} potential VM dispatch loops", "debug")
    return code

def devirtualize_accumulator(code, verbose=False):
    pattern = r'accumulator\s*=\s*([^;]+);\s*(if\s+accumulator\s*<\s*\d+.*?end)'
    def repl(m):
        expr = m.group(1)
        body = m.group(2)
        body = re.sub(r'accumulator\s*<\s*(\d+)', r'phase < PHASE_\1', body)
        return f"-- VM state: {expr}\n{body}"
    new_code, n = re.subn(pattern, repl, code, flags=re.DOTALL)
    if verbose and n:
        log(f"Devirtualized {n} accumulator state machines", "debug")
    return new_code

def flatten_opcode_dispatch(code, verbose=False):
    pattern = r'local\s+(\w+)\s*=\s*(\w+)\[(\w+)\]\s*;\s*((?:if\s+\1\s*==\s*\d+\s+then.*?end\s*)+)'
    def repl(m):
        op_var = m.group(1)
        array = m.group(2)
        index = m.group(3)
        cases = m.group(4)
        case_pattern = rf'if\s+{re.escape(op_var)}\s*==\s*(\d+)\s+then\s*(.*?)\s*end'
        case_list = []
        for cm in re.finditer(case_pattern, cases, re.DOTALL):
            opcode, body = cm.group(1), cm.group(2)
            case_list.append(f"    -- OP_{opcode}\n    {body.strip()}")
        new_body = '\n'.join(case_list)
        return f"-- VM dispatch from {array}[{index}]\n{new_body}"
    new_code, n = re.subn(pattern, repl, code, flags=re.DOTALL)
    if verbose and n:
        log(f"Flattened {n} opcode dispatch tables", "debug")
    return new_code

def remove_goto_jumps(code, verbose=False):
    code, n1 = re.subn(r'goto\s*\[([^\]]+)\]', r'-- indirect goto: \1', code)
    if verbose and n1:
        log(f"Removed {n1} indirect goto statements", "debug")
    return code

def resolve_vm_phases(code, verbose=False):
    pattern = r'phase\s*=\s*(\w+)\s*;\s*if\s+\1\s*==\s*(\d+)\s+then'
    new_code, n = re.subn(pattern, r'-- PHASE_\2_START\nif \1 == \2 then', code)
    if verbose and n:
        log(f"Marked {n} VM phase transitions", "debug")
    return new_code

def simulate_vm_bytecode(code, verbose=False):
    pattern = r'local\s+(\w+)\s*=\s*{([\d,\s]+)}'
    def repl(m):
        name = m.group(1)
        values = m.group(2)
        nums = re.findall(r'\d+', values)
        if len(nums) > 20:
            summary = nums[:10] + ['...'] + nums[-5:]
        else:
            summary = nums
        return f"-- VM BYTECODE {name}: [{', '.join(summary)}]\nlocal {name} = {{{values}}}"
    new_code, n = re.subn(pattern, repl, code)
    if verbose and n:
        log(f"Commented {n} VM bytecode arrays", "debug")
    return new_code

def vm_deobfuscation_pipeline(code, verbose=False):
    steps = [
        detect_vm_dispatch_loops,
        devirtualize_accumulator,
        flatten_opcode_dispatch,
        remove_goto_jumps,
        resolve_vm_phases,
        simulate_vm_bytecode,
    ]
    for func in steps:
        if verbose:
            log(f"VM decoding: {func.__name__}", "debug")
        code = func(code, verbose)
    return code

def pretty_print(code, verbose=False):
    lines = []
    indent = 0
    for line in code.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(('end', 'until', 'elseif', 'else')):
            indent = max(0, indent - 1)
        lines.append('    ' * indent + stripped)
        if stripped.endswith('then') or stripped.endswith('do') or stripped.startswith('function'):
            indent += 1
    return '\n'.join(lines)

def deobfuscate(code, verbose=False):
    steps = [
        find_and_decrypt_strings,
        resolve_constant_arrays,
        remove_antitamper,
        vm_deobfuscation_pipeline,
        simplify_control_flow,
        remove_junk,
        demangle_names,
        reconstruct_string_concat,
    ]
    for func in steps:
        if verbose:
            log(f"Running: {func.__name__}", "debug")
        code = func(code, verbose)
    code = pretty_print(code, verbose)
    return code

def main():
    parser = argparse.ArgumentParser(description="Prometheus Lua Deobfuscator with VM decoding")
    parser.add_argument("input", help="Input Lua file (obfuscated)")
    parser.add_argument("output", nargs="?", help="Output file (default: input_deobf.lua)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"Pol-decoder {VERSION}")
    args = parser.parse_args()

    infile = args.input
    outfile = args.output if args.output else infile.replace('.lua', '_deobf.lua')
    if not os.path.exists(infile):
        log(f"File not found: {infile}", "error")
        sys.exit(1)

    with open(infile, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()

    if args.verbose:
        log(f"Loaded {len(code)} bytes from {infile}", "debug")

    result = deobfuscate(code, args.verbose)

    if result == code and args.verbose:
        log("WARNING: No changes were made. The obfuscation pattern may be unsupported.", "warning")

    with open(outfile, 'w', encoding='utf-8') as f:
        f.write(result)

    log(f"Deobfuscated script written to {outfile}", "info")

if __name__ == "__main__":
    main()