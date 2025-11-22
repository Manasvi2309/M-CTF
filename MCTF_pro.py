#!/usr/bin/env python3
# MCTF_pro.py → Manasvi's Ultimate All-in-One CTF Weapon 2025
# Zero dependency (external tools needed) | Single file | Made with love by Gemini for Manasvi

import os
import re
import sys
import base64
import urllib.parse
import subprocess
import shlex

# --- UTILS ---

def header_print(title):
    """Prints a formatted header."""
    print(f"\n\033[94m--- {title.upper()} ---\\033[0m")

def run(cmd, silent=False):
    """Runs a command and returns its output, handling common errors."""
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=30).decode(errors='ignore')
        if not silent and output:
            print(output)
        return output
    except FileNotFoundError:
        tool = cmd.split()[0]
        if not silent:
            print(f"\033[91mError: '{tool}' not found. Is it installed and in your PATH?\\033[0m")
        return ""
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        # Don't print errors for silent commands unless they are very verbose
        if not silent and len(e.output) < 500:
            print(e.output.decode(errors='ignore'))
        return e.output.decode(errors='ignore')

# --- DECODING ---

def decode_layers(data, max_layers=20):
    """Recursively decodes common CTF encodings."""
    header_print("Decoding Layers")
    cur_data = data.strip()
    found_something = False
    for i in range(1, max_layers + 1):
        original_data = cur_data
        decoders = {
            'Base64': lambda s: base64.b64decode(s.encode('utf-8', 'ignore') + b'===').decode(errors='ignore'),
            'Base32': lambda s: base64.b32decode(s.encode('utf-8', 'ignore') + b'====').decode(errors='ignore'),
            'Base16/Hex': lambda s: bytes.fromhex(s).decode(errors='ignore'),
            'URL': urllib.parse.unquote,
            'Binary': lambda s: ''.join([chr(int(b, 2)) for b in s.split()]),
            'ROT13': lambda s: ''.join(
                chr(ord(c) + 13) if 'a' <= c <= 'm' or 'A' <= c <= 'M' else
                chr(ord(c) - 13) if 'n' <= c <= 'z' or 'N' <= c <= 'Z' else c
                for c in s
            )
        }

        for name, func in decoders.items():
            try:
                # For binary, we need to format it first
                if name == 'Binary':
                    temp_data = re.sub(r'[^01\s]', '', cur_data)
                    if not temp_data or len(temp_data.replace(" ", "")) % 8 != 0: continue
                    # Ensure space between bytes
                    if ' ' not in temp_data:
                        temp_data = ' '.join(temp_data[j:j+8] for j in range(0, len(temp_data), 8))
                    new_data = func(temp_data)
                else:
                    new_data = func(cur_data)
                
                if new_data.strip() and new_data != cur_data and re.search(r'flag|ctf|{|pico|ractf', new_data, re.IGNORECASE):
                    print(f"Layer {i} ({name}): \033[92m{new_data.strip()}\033[0m")
                    cur_data = new_data.strip()
                    found_something = True
                    break 
            except Exception:
                continue
        
        if cur_data == original_data: # If no decoder changed the data, stop
            if not found_something: print("No obvious layered encodings found.")
            return cur_data
    return cur_data

# --- SOLVERS ---

def solve_text(text):
    """Analyzes a piece of text for flags, encodings, hashes, and crypto."""
    header_print("Analyzing Text")
    
    flags = re.findall(r'([a-zA-Z0-9_]+{.*?})', text, re.IGNORECASE)
    if flags:
        for flag in flags: print(f"FLAG PAKAD LIYA → \033[92m{flag}\033[0m")
        return

    decoded_text = decode_layers(text)

    header_print("Caesar Cipher Bruteforce")
    found_rot = False
    for i in range(1, 26):
        shifted = "".join(
            chr((ord(c) - ord('a') - i) % 26 + ord('a')) if 'a' <= c <= 'z' else
            chr((ord(c) - ord('A') - i) % 26 + ord('A')) if 'A' <= c <= 'Z' else c
            for c in decoded_text
        )
        if re.search(r'flag|ctf|{|pico|ractf', shifted, re.IGNORECASE):
            print(f"ROT-{i} → \033[92m{shifted.strip()}\033[0m")
            found_rot = True
    if not found_rot: print("No obvious Caesar shifts found.")

    h = text.strip().lower()
    if re.fullmatch(r'^[a-f0-9]{32}$', h): header_print("MD5 Hash Detected"); print("Try: hashcat -m 0 or crackstation.net")
    if re.fullmatch(r'^[a-f0-9]{40}$', h): header_print("SHA1 Hash Detected"); print("Try: hashcat -m 100")
    if re.fullmatch(r'^[a-f0-9]{64}$', h): header_print("SHA256 Hash Detected"); print("Try: hashcat -m 1400")
    if h.startswith('$2y$') or h.startswith('$2a$'): header_print("BCrypt Hash Detected"); print("Try: hashcat -m 3200")

    n = re.search(r'n\s*[:=]\s*(\d+)', text, re.IGNORECASE)
    e = re.search(r'e\s*[:=]\s*(\d+)', text, re.IGNORECASE)
    c = re.search(r'c\s*[:=]\s*(\d+)', text, re.IGNORECASE)
    if n and e and c:
        header_print("RSA Parameters Detected (n, e, c)")
        print("Try RsaCtfTool: python RsaCtfTool.py -n {} -e {} --uncipher {}".format(n.group(1), e.group(1), c.group(1)))

def solve_file(filepath):
    """Analyzes a file based on its type."""
    header_print(f"Analyzing File: {filepath}")
    fpath_safe = shlex.quote(filepath)
    ext = os.path.splitext(filepath)[1].lower()
    
    header_print("Universal File Analysis")
    run(f"strings {fpath_safe} | grep -iE 'flag|ctf|pico|{{'")
    run(f"exiftool {fpath_safe}")

    if ext in ['.png', '.jpg', '.jpeg', '.bmp', '.gif']:
        header_print("Image Stego Analysis")
        run(f"zsteg -a {fpath_safe}")
        run(f"steghide extract -sf {fpath_safe} -p '' -xf out.txt")
        print("Also try steghide with passwords, e.g.: steghide extract -sf {} -p <pass>".format(fpath_safe))

    elif ext in ['.pcap', '.pcapng']:
        header_print("PCAP Forensics Analysis")
        run(f"tshark -r {fpath_safe} -Y 'http.request or http.response' -T fields -e text | grep -iE 'flag|ctf'")
        run(f"tshark -r {fpath_safe} -Y 'ftp-data' -T fields -e text | grep -iE 'flag|ctf'")
        run(f"tshark -r {fpath_safe} -Y 'dns.qry.name || dns.resp.name' -T fields -e dns.qry.name -e dns.resp.name | grep -iE 'flag|ctf'")

    else: # Assumed to be a binary
        header_print("Binary Analysis (Pwn/RE)")
        run(f"file {fpath_safe}")
        run(f"checksec --file={fpath_safe}")
        
        if "ELF" in run(f"file {fpath_safe}", silent=True):
            strings_out = run(f"rabin2 -z {fpath_safe}", silent=True)
            if any(s in strings_out for s in ['win', 'system', '/bin/sh', 'flag']):
                header_print("Potential Win Function / System Call")
                print("Found interesting strings. Generating pwntools exploit template...")
                template = f"""
from pwn import *
elf = context.binary = ELF({fpath_safe}, checksec=False)
# p = process()
# p = remote('host', 1337)
# gdb.attach(p, gdbscript='pattern create 200\nr')
offset = 0 # TODO: Find offset with pattern
payload = flat([
    b'A' * offset,
    # ROP chain here
])
# p.sendline(payload)
# p.interactive()
"""
                print(template)

    header_print("File Carving")
    run(f"binwalk -eM {fpath_safe}")
    run(f"foremost -i {fpath_safe} -o foremost_output")

# --- MAIN LOGIC ---

def main():
    """Main function to handle input and delegate to solvers."""
    print(r"""
\033[95m
╔═══════════════════════════════════════════════════════════════╗
║                   MCTF_pro – All-in-One Solver                 ║
║                Manasvi's Indian CTF Weapon 2025                ║
║         Crypto • Stego • Web • Forensics • Pwn • Misc          ║
╚═══════════════════════════════════════════════════════════════╝
\033[0m""")

    if len(sys.argv) > 1:
        arg_str = ' '.join(sys.argv[1:])
        parts = arg_str.split()
        if len(parts) == 2 and parts[1].isdigit():
            os.system(f"nc {parts[0]} {parts[1]}")
        elif arg_str.startswith('http://') or arg_str.startswith('https://'):
            header_print(f"Fetching URL: {arg_str}")
            content = run(f"wget -qO- {shlex.quote(arg_str)}", silent=True)
            if content:
                solve_text(content)
                if '?' in arg_str and '=' in arg_str:
                    header_print("Potential SQL Injection")
                    print(f"Try: sqlmap -u '{arg_str}' --dbs --batch")
        elif os.path.isfile(arg_str):
            solve_file(arg_str)
        else:
            solve_text(arg_str)
        return

    print("Interactive mode → paste text / file path / URL / [nc] host port")
    while True:
        try:
            inp = input("\033[95mMCTF> \033[0m").strip()
            if inp.lower() in ['exit', 'q']: break
            if not inp: continue

            parts = inp.split()
            if (inp.startswith('nc ') and len(parts) == 3) or (len(parts) == 2 and parts[1].isdigit()):
                host = parts[1] if inp.startswith('nc ') else parts[0]
                port = parts[2] if inp.startswith('nc ') else parts[1]
                os.system(f"nc {host} {port}")
            elif inp.startswith('http://') or inp.startswith('https://'):
                header_print(f"Fetching URL: {inp}")
                content = run(f"wget -qO- {shlex.quote(inp)}", silent=True)
                if content:
                    solve_text(content)
                    if '?' in inp and '=' in inp:
                        header_print("Potential SQL Injection")
                        print(f"Try: sqlmap -u '{inp}' --dbs --batch")
            elif os.path.isfile(inp):
                solve_file(inp)
            else:
                solve_text(inp)
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

if __name__ == "__main__":
    main()
