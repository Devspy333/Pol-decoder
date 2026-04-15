# Pol-decoder – Prometheus Lua Deobfuscator

[![Python](https://img.shields.io/badge/python-3.6%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A powerful Python tool to reverse obfuscation applied by the **Prometheus Lua Obfuscator** (and similar tools). Works on multiple variants, including Moonsec and other VM-based obfuscators.

## Features

- ✅ **String decryption** – Dual PRNG (LCG + XOR) with auto pattern detection  
- ✅ **Constant array inlining** – Resolves direct and arithmetic table accesses  
- ✅ **Anti‑tamper removal** – Strips `pcall`, `debug.getinfo`, `sethook`, `load` etc.  
- ✅ **Control flow simplification** – Converts `else if` → `elseif`, removes dead branches  
- ✅ **Junk code elimination** – Deletes useless assignments, empty loops, dummy functions  
- ✅ **Name demangling** – Maps single‑letter variables to readable names  
- ✅ **String concatenation reconstruction** – Merges `table.concat({...})` fragments  
- ✅ **Pretty printing** – Adds proper indentation  
- ✅ **Verbose mode** – Shows each step and pattern matches  

## Requirements

- Python 3.6+  
- Optional: `colorama` (for colored output) – install via `pip install -r requirements.txt`

## Installation

```bash
git clone https://github.com/Devspy333/Pol-decoder.git
cd Pol-decoder
pip install -r requirements.txt