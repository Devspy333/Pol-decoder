#!/usr/bin/env python3
import re
import ast
import base64
import sys
import os

# Fallback if colorama not installed
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

def log(message, level="info"):
    if HAS_COLOR:
        colors = {"debug": Fore.CYAN, "info": Fore.GREEN, "warning": Fore.YELLOW, "error": Fore.RED}
        print(f"[{colors.get(level, '')}{level.upper()}{Style.RESET_ALL}] {message}")
    else:
        print(f"[{level.upper()}] {message}")

class PrometheusStringDecryptor:
    def __init__(self):
        self.lcg_mult = 1103515245
        self.lcg_inc = 12345
        self.lcg_mod = 2**45
        self.xor_mult = 257
        self.xor_mod = 65537

    def decrypt(self, enc, seed):
        lcg = seed % self.lcg_mod
        xor = 1
        res = []
        for ch in enc:
            lcg = (lcg * self.lcg_mult + self.lcg_inc) % self.lcg_mod
            xor = (xor * self.xor_mult) % self.xor_mod
            if xor == 1:
                xor = (xor * self.xor_mult) % self.xor_mod
            key = (lcg + xor) % 256
            res.append(chr(ord(ch) ^ key))
        return ''.join(res)

def decrypt_prometheus_strings(code, verbose=False):
    decryptor = PrometheusStringDecryptor()
    # Multiple patterns to catch different Prometheus versions
    patterns = [
        # Pattern 1: function name(param) local state = seed
        r'function\s+([\w_]+)\s*\(\s*([\w_]+)\s*\)\s*local\s+[\w_]+\s*=\s*(\d+)',
        # Pattern 2: local name = function(param) local state = seed
        r'local\s+([\w_]+)\s*=\s*function\s*\(\s*([\w_]+)\s*\)\s*local\s+[\w_]+\s*=\s*(\d+)',
        # Pattern 3: function name(param) local _ = seed (underscore variable)
        r'function\s+([\w_]+)\s*\(\s*([\w_]+)\s*\)\s*local\s+_\s*=\s*(\d+)',
        # Pattern 4: simple pattern without local state (just seed as literal)
        r'function\s+([\w_]+)\s*\(\s*([\w_]+)\s*\)\s*local\s+\w+\s*=\s*(\d+)',
    ]
    found = False
    for pattern in patterns:
        matches = list(re.finditer(pattern, code))
        if matches:
            if verbose:
                log(f"Found decryptor using pattern: {pattern[:50]}...", "debug")
            for match in matches:
                func = match.group(1)
                seed = int(match.group(3))
                if verbose:
                    log(f"  -> Function: {func}, seed: {seed}", "debug")
                # Replace calls: func("encrypted")
                call_pat = rf'{func}\s*\(\s*"([^"]+)"\s*\)'
                new_code = re.sub(call_pat, lambda m, s=seed: f'"{decryptor.decrypt(m.group(1), s)}"', code)
                if new_code != code:
                    code = new_code
                    found = True
                    if verbose:
                        log(f"  -> Decrypted {len(re.findall(call_pat, code))} strings", "debug")
            if found:
                break
    if not found and verbose:
        log("No string decryption pattern matched. Try manually checking the script structure.", "warning")
    return code

def resolve_constant_arrays(code, verbose=False):
    count = 0
    for match in re.finditer(r'local\s+([\w_]+)\s*=\s*{([^}]+)}', code, re.DOTALL):
        name, content = match.groups()
        elems = []
        for elem in re.split(r',\s*(?![^{]*})', content):
            elem = elem.strip()
            if elem.startswith(('"', "'")):
                elems.append(elem)
            elif elem.isdigit():
                elems.append(elem)
            else:
                elems.append('nil')
        if len(elems) > 0 and verbose:
            log(f"Found constant array {name} with {len(elems)} elements", "debug")
        for i, val in enumerate(elems, 1):
            new_code = re.sub(rf'{re.escape(name)}\[\s*{i}\s*\]', val, code)
            if new_code != code:
                count += 1
                code = new_code
    if verbose and count > 0:
        log(f"Resolved {count} constant array references", "debug")
    return code

def remove_antitamper(code, verbose=False):
    patterns = [
        (r'pcall\s*\([^)]*\)\s*', ''),
        (r'debug\.getinfo\s*\([^)]*\)\s*', ''),
        (r'debug\.sethook\s*\([^)]*\)\s*', ''),
        (r'local valid=true;.*?if valid then else.*?end', 'local valid=true;'),
    ]
    removed = 0
    for pat, repl in patterns:
        new_code = re.sub(pat, repl, code, flags=re.DOTALL)
        if new_code != code:
            removed += 1
            code = new_code
    if verbose and removed:
        log(f"Removed {removed} anti‑tamper patterns", "debug")
    return code

def simplify_control_flow(code, verbose=False):
    old_len = len(code)
    code = re.sub(r'else\s+if', 'elseif', code)
    code = re.sub(r'if\s+(\w+)\s+then\s+\1\s*=\s*\1\s+end', '', code)
    if verbose and len(code) != old_len:
        log("Simplified control flow", "debug")
    return code

def demangle_names(code, verbose=False):
    mapping = {
        'V': 'table', 'f': 'func', 'R': 'string', 'O': 'math', 'N': 'num',
        'X': 'char', 'G': 'table_insert', 'p': 'string_sub', 'i': 'concat',
        't': 'accumulator', 'K': 'bit32', 'D': 'buffer', 'S': 'state',
    }
    changes = 0
    for old, new in mapping.items():
        new_code = re.sub(rf'\b{old}\b(?![\'"])', new, code)
        if new_code != code:
            changes += 1
            code = new_code
    if verbose and changes:
        log(f"Demangled {changes} variable names", "debug")
    return code

def remove_junk(code, verbose=False):
    patterns = [
        (r'local function \w+\(\)\s*return ""\s*end', ''),
        (r'if \w+ == -\d+ then \w+ = -\d+ end', ''),
        (r'for \w+ = -\d+,#\w+,-?\d+ do end', ''),
        (r'\w+ = \w+ [+-] \d+\s*$', '', re.MULTILINE),
        (r'local \w+ = nil\s*', ''),
    ]
    removed = 0
    for pat, repl, *flags in patterns:
        flag = flags[0] if flags else 0
        new_code = re.sub(pat, repl, code, flags=flag)
        if new_code != code:
            removed += 1
            code = new_code
    if verbose and removed:
        log(f"Removed {removed} junk code patterns", "debug")
    return code

def pretty_print(code, verbose=False):
    lines = []
    indent = 0
    for line in code.splitlines():
        line = line.strip()
        if line.startswith(('end', 'until', 'elseif', 'else')):
            indent = max(0, indent - 1)
        lines.append('    ' * indent + line)
        if line.endswith('then') or line.endswith('do') or line.startswith('function'):
            indent += 1
    return '\n'.join(lines)

def deobfuscate(code, verbose=False):
    if verbose:
        log("Starting deobfuscation pipeline...", "info")
    steps = [
        ("Decrypting strings", decrypt_prometheus_strings),
        ("Resolving constant arrays", resolve_constant_arrays),
        ("Removing anti‑tamper", remove_antitamper),
        ("Simplifying control flow", simplify_control_flow),
        ("Demangling names", demangle_names),
        ("Removing junk code", remove_junk),
        ("Pretty printing", pretty_print),
    ]
    for name, func in steps:
        if verbose:
            log(f"Running: {name}", "debug")
        code = func(code, verbose)
    return code

def main():
    if len(sys.argv) < 2:
        print("Usage: python prometheus_deobf.py <input.lua> [output.lua]")
        print("       Add -v or --verbose for detailed output")
        sys.exit(1)
    infile = sys.argv[1]
    outfile = None
    verbose = '-v' in sys.argv or '--verbose' in sys.argv
    # Parse args
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg in ('-v', '--verbose'):
            continue
        if not outfile and infile != arg:
            outfile = arg
    if not outfile:
        outfile = infile.replace('.lua', '_deobf.lua')
    if not os.path.exists(infile):
        log(f"File not found: {infile}", "error")
        sys.exit(1)
    with open(infile, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()
    if verbose:
        log(f"Input file size: {len(code)} bytes", "debug")
    result = deobfuscate(code, verbose)
    if result == code and verbose:
        log("WARNING: No changes were made. The patterns may not match your Prometheus version.", "warning")
        log("Try manually inspecting the obfuscated script for decryption function patterns.", "warning")
    with open(outfile, 'w', encoding='utf-8') as f:
        f.write(result)
    log(f"Deobfuscated script written to {outfile}", "info")

if __name__ == "__main__":
    main()
