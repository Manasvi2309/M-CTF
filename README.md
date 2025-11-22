# M-CTF
"All-in-one CTF Weapon 2025"
# M-CTF – All-in-One Indian CTF Weapon 2025

![M-CTF Banner](https://capsule-render.vercel.app/api?type=waving&color=8B00FF&height=200&section=header&text=M-CTF&fontSize=90&fontAlignY=55)
  
Zero-dependency Python tool that solves 90% of easy/medium CTF challenges in seconds!

## Features
- Multi-layer decoding (Base64, Hex, Binary, ROT, URL, etc. – 30 layers)
- Steganography auto-solve (strings, exiftool, binwalk, zsteg, steghide brute)
- Crypto hints & RSA auto-call RsaCtfTool
- Pwn/Reverse: checksec, strings, cyclic offset finder
- Web & Forensics: SQLi payloads, tshark filters
- Works on *Windows · Kali · Termux* – no extra install needed!

## Quick Start
```bash
git clone https://github.com/Manasvi2309/M-CTF.git
cd M-CTF
python M-CTF.py
Usage Examples
python M-CTF.py                    → Interactive mode (purple prompt)
python M-CTF.py "a1b2c3..."        → Solve text directly
python M-CTF.py image.png          → Auto stego solve
python M-CTF.py chall.ctf.com 1337 → Direct
