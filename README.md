# unveil (unv)

Static triage CLI for executable and packaged artifacts.

unv is built for fast, local inspection when you need signal immediately. 
Not a framework, not a sandbox, not exploitation.

---

## What it does

- File identification and metadata
- Hashing (MD5 / SHA1 / SHA256)
- Import / symbol inspection
- Entropy analysis
- Strings extraction
- Manifest parsing (APK / IPA)
- JSON-first output

No execution. No guessing.

---

## Supported formats

PE • ELF • Mach-O • APK • IPA • ZIP / archives

---

## Install

pipx install git+https://github.com/Pa7ch3s/unv.git

---

## Usage

unv scan /path/to/file  
unv strings /path/to/file  
unv entropy /path/to/file  

---

## Relationship

- unv → fast static triage
- iiPry → thick-client surface intelligence

Separate tools. Different purposes.

---

## License

MIT
