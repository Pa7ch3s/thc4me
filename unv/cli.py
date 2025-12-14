#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
THC4me CLI — first-cut static scanner + sqlmap-style toolkit
Usage examples:
  unv.cli.py scan app.apk --pretty --out out.json
  unv.cli.py strings app.apk --min-len 5 --max-lines 2000
  unv.cli.py imports sample.exe
  unv.cli.py entropy sample.exe
  unv.cli.py manifest app.apk
  unv.cli.py tools --check
  unv.cli.py manual
"""

import argparse, hashlib, json, mimetypes, os, re, shutil, subprocess, sys, uuid
from datetime import datetime
from pathlib import Path

# -------- Optional deep parsers --------
try:
    from unv_static_parser import analyze as static_analyze  # preferred
except Exception:
    static_analyze = None

try:
    import lief  # cross-format binary parsing (optional)
except Exception:
    lief = None

try:
    import pefile  # deeper PE parsing (optional)
except Exception:
    pefile = None

# -------- Regexes / constants ----------
CREDS_RE = re.compile(
    r"(?i)(?:api[_-]?key|apikey|password|pass|secret|token|auth[_-]?key|client_secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})['\"]?"
)

VERSION = "0.2.0"

# -------- Helpers ----------------------
def run_cmd(cmd, timeout=20):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    return p.stdout.decode("utf-8", "ignore"), p.stderr.decode("utf-8", "ignore"), p.returncode

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def guess_file_type(path):
    file_bin = shutil.which("file")
    if file_bin:
        out, _, rc = run_cmd([file_bin, "--brief", "--mime-type", path])
        if rc == 0 and out.strip():
            return out.strip()
    mt, _ = mimetypes.guess_type(path)
    return mt or "application/octet-stream"

def extract_strings(path, min_len=4, max_lines=20000):
    strings_bin = shutil.which("strings")
    if strings_bin:
        out, _, rc = run_cmd([strings_bin, "-n", str(min_len), path], timeout=40)
        if rc == 0 and out:
            lines = out.splitlines()
            return [ln.rstrip() for ln in lines[:max_lines]]
    # fallback naive extraction
    res, cur = [], []
    with open(path, "rb") as f:
        data = f.read()
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                res.append("".join(cur))
                if len(res) >= max_lines:
                    return res
            cur = []
    if len(cur) >= min_len and len(res) < max_lines:
        res.append("".join(cur))
    return res

def get_imports_with_lief(path):
    if not lief: return []
    try:
        binobj = lief.parse(path)
        imports = []
        for imp in getattr(binobj, "imports", []):
            imports.append({"name": imp.name, "entries": [e.name for e in imp.entries]})
        return imports
    except Exception:
        return []

def get_imports_with_pefile(path):
    if not pefile: return []
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()
        res = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                dll = imp.dll.decode(errors="ignore") if isinstance(imp.dll, bytes) else str(imp.dll)
                syms = [(i.name.decode(errors="ignore") if i.name else "") for i in imp.imports]
                res.append({"name": dll, "entries": syms})
        return res
    except Exception:
        return []

def file_entropy(path):
    import math
    with open(path, "rb") as f:
        data = f.read()
    if not data: return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    n = len(data)
    for v in freq.values():
        p = v / n
        ent -= p * math.log2(p)
    return ent

def list_archive(path):
    unzip = shutil.which("unzip")
    if unzip:
        out, _, rc = run_cmd([unzip, "-l", path])
        if rc == 0 and out:
            return out
    return ""

def dump_apk_manifest(path):
    aapt = shutil.which("aapt") or shutil.which("aapt2")
    if aapt:
        out, _, rc = run_cmd([aapt, "dump", "xmltree", path, "AndroidManifest.xml"], timeout=30)
        if rc == 0 and out:
            return out
    return ""

def dump_ipa_info_plist(path):
    # naive: unzip then plutil; keep simple for now
    tmpdir = None
    try:
        unzip = shutil.which("unzip")
        plutil = shutil.which("plutil")
        if not unzip or not plutil:
            return ""
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as d:
            tmpdir = d
            out, _, rc = run_cmd([unzip, "-q", path, "-d", d])
            # locate Info.plist
            plist = None
            for root, _, files in os.walk(d):
                for f in files:
                    if f == "Info.plist":
                        plist = os.path.join(root, f)
                        break
                if plist: break
            if not plist: return ""
            out, _, rc = run_cmd([plutil, "-convert", "json", plist, "-o", "-"])
            if rc == 0:
                return out
            return ""
    except Exception:
        return ""
    finally:
        pass

# -------- Core: scan --------
def scan_file(path: Path):
    path = str(path)
    basename = os.path.basename(path)
    fid = str(uuid.uuid4())
    sha = sha256_of_file(path)
    ftype = guess_file_type(path)

    scan_obj = {
        "scan": {
            "id": fid,
            "filename": basename,
            "sha256": sha,
            "filetype": ftype,
            "scanned_at": datetime.utcnow().isoformat() + "Z"
        },
        "artifacts": [],
        "findings": []
    }

    # Basic metadata artifact
    scan_obj["artifacts"].append({
        "type": "metadata",
        "name": "file_info",
        "value": f"{basename}",
        "detail": f"mime={ftype}",
        "evidence_path": path
    })

    # Archive helpers and mobile manifests
    lower = basename.lower()
    if lower.endswith((".apk", ".jar", ".ipa", ".zip")):
        idx = list_archive(path)
        if idx:
            scan_obj["artifacts"].append({
                "type":"archive_index","name":"unzip_list",
                "value": idx[:10000],
                "detail":"listing of archive contents","evidence_path":""
            })
        if lower.endswith(".apk"):
            man = dump_apk_manifest(path)
            if man:
                scan_obj["artifacts"].append({
                    "type":"manifest","name":"AndroidManifest.xml",
                    "value": man[:10000],
                    "detail":"aapt xmltree","evidence_path":""
                })
        elif lower.endswith(".ipa"):
            info = dump_ipa_info_plist(path)
            if info:
                scan_obj["artifacts"].append({
                    "type":"manifest","name":"Info.plist",
                    "value": info[:10000],
                    "detail":"plutil json","evidence_path":""
                })

    # Strings
    strs = extract_strings(path, min_len=4, max_lines=20000)
    if strs:
        sample = "\n".join(strs[:500])
        scan_obj["artifacts"].append({
            "type":"strings_sample","name":"strings_top500",
            "value": sample,
            "detail": f"{len(strs)} total strings",
            "evidence_path":""
        })

    # Secrets regex
    findings = []
    seen = set()
    for s in strs[:5000]:
        m = CREDS_RE.search(s)
        if not m: continue
        keyval = m.group(1)
        if keyval in seen: continue
        seen.add(keyval)
        evidence = s.strip()
        findings.append({
            "code": "TC-HARDCODED-CREDS",
            "title": "Hard-coded credential (Thick Client)",
            "severity": "High",
            "confidence": "Firm",
            "description": f"Detected possible hard-coded secret near: {keyval}",
            "evidence": evidence,
            "offsets": []
        })
        scan_obj["artifacts"].append({
            "type": "strings_match",
            "name": "hardcoded_credential",
            "value": keyval,
            "detail": evidence,
            "evidence_path": ""
        })
        if len(findings) >= 25:
            break

    # Certificates by string probe
    certs = [s for s in strs if "BEGIN CERTIFICATE" in s or "-----BEGIN CERTIFICATE-----" in s]
    if certs:
        for idx, c in enumerate(certs[:5]):
            scan_obj["artifacts"].append({
                "type":"certificate","name":f"cert_{idx}",
                "value": c[:2000],
                "detail":"embedded certificate (truncated)",
                "evidence_path":""
            })

    # Hash
    scan_obj["artifacts"].append({
        "type":"hash","name":"sha256","value":sha,
        "detail":"","evidence_path":path
    })

    # Imports summary (optional, quick peek)
    imps = get_imports_with_lief(path) or get_imports_with_pefile(path)
    if imps:
        scan_obj["artifacts"].append({
            "type":"imports","name":"imports_list",
            "value": json.dumps(imps[:200]),
            "detail": f"imports_count={len(imps)}",
            "evidence_path": path
        })

    # Entropy heuristic
    try:
        ent = file_entropy(path)
        scan_obj["artifacts"].append({
            "type":"entropy","name":"file_entropy",
            "value": f"{ent:.4f}",
            "detail":"Shannon entropy","evidence_path": path
        })
        if ent > 7.5:
            findings.append({
                "code":"TC-HIGH-ENTROPY",
                "title":"High entropy blob (possible packing/encryption)",
                "severity":"Medium",
                "confidence":"Tentative",
                "description":f"File entropy {ent:.2f} suggests packed or encrypted content.",
                "evidence": f"entropy={ent:.2f}"
            })
    except Exception:
        pass

    if findings:
        scan_obj["findings"].extend(findings)

    # Optional deeper analysis via unv_static_parser
    if static_analyze:
        try:
            deep = static_analyze(path)
            if isinstance(deep, dict):
                scan_obj["artifacts"].extend(deep.get("artifacts", []))
                scan_obj["findings"].extend(deep.get("findings", []))
        except Exception:
            # ignore deep errors, keep baseline output
            pass

    # Large strings note
    if len(strs) > 20000:
        scan_obj["artifacts"].append({
            "type":"note","name":"large_string_pool",
            "value":str(len(strs)),
            "detail":"Large number of printable strings, likely packed resources",
            "evidence_path":""
        })

    return scan_obj

# -------- Subcommands ------------------
def cmd_scan(args):
    p = Path(args.file)
    if not p.exists():
        print(json.dumps({"error":"file not found"})); sys.exit(2)
    result = scan_file(p)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2 if args.pretty else None)
    print(json.dumps(result, indent=2 if args.pretty else None))

def cmd_strings(args):
    p = Path(args.file)
    if not p.exists():
        print("error: file not found"); sys.exit(2)
    lines = extract_strings(str(p), min_len=args.min_len, max_lines=args.max_lines)
    for ln in lines: print(ln)

def cmd_imports(args):
    p = Path(args.file)
    if not p.exists():
        print("error: file not found"); sys.exit(2)
    imps = get_imports_with_lief(str(p)) or get_imports_with_pefile(str(p))
    print(json.dumps(imps, indent=2))

def cmd_entropy(args):
    p = Path(args.file)
    if not p.exists():
        print("error: file not found"); sys.exit(2)
    ent = file_entropy(str(p))
    print(f"{ent:.6f}")

def cmd_manifest(args):
    p = Path(args.file)
    if not p.exists():
        print("error: file not found"); sys.exit(2)
    name = p.name.lower()
    if name.endswith(".apk"):
        out = dump_apk_manifest(str(p))
    elif name.endswith(".ipa"):
        out = dump_ipa_info_plist(str(p))
    elif name.endswith((".jar",".zip")):
        out = list_archive(str(p))
    else:
        out = ""
    print(out if out else "(no manifest or listing available)")

def cmd_tools(args):
    tools = {
        "file": shutil.which("file"),
        "strings": shutil.which("strings"),
        "unzip": shutil.which("unzip"),
        "aapt": shutil.which("aapt") or shutil.which("aapt2"),
        "plutil": shutil.which("plutil"),
    }
    libs = {
        "lief": bool(lief),
        "pefile": bool(pefile),
        "static_parser": bool(static_analyze),
    }
    info = {"tools": tools, "libs": libs, "version": VERSION}
    if args.check:
        ok = all(tools.values()) and libs["static_parser"]
        print(json.dumps({"ok": ok, **info}, indent=2))
    else:
        print(json.dumps(info, indent=2))

MANUAL_TEXT = """THC4me Manual (first cut)

Purpose:
  Static triage of thick-client binaries and packages (EXE/DLL/DMG/IPA/APK/JAR/ZIP)
  with sqlmap-style ergonomics. Never executes targets.

Primary command:
  scan <file> [--out OUT.json] [--pretty]
    - Produces JSON: { scan, artifacts[], findings[] }
    - Artifacts include: metadata, strings sample, imports (if available),
      entropy, archive index, mobile manifests, certificates by probe, hashes.
    - Findings include: high-entropy heuristic, hard-coded credential regex hits.

Toolkit commands:
  strings <file> [--min-len N] [--max-lines M]
  imports <file>
  entropy <file>
  manifest <file>   # APK -> AndroidManifest, IPA -> Info.plist JSON, JAR/ZIP -> listing
  tools [--check]   # show tool/library availability and version

Integration:
  - Burp extension can call `scan` and store results in SQLite.
  - Daemon mode: wrap this CLI from your FastAPI service or call directly.

Security:
  - No dynamic execution. Static-only.
  - Consider sandbox/container for untrusted samples.

Roadmap:
  - YARA rules
  - Androguard/jadx/CFR hooks
  - Ghidra headless queue
  - IPC/pipe signatures, updater-channel checks
"""

def cmd_manual(_args):
    print(MANUAL_TEXT)

# -------- Main -------------------------
def build_parser():
    p = argparse.ArgumentParser(description="THC4me minimal CLI scanner and toolkit")
    p.add_argument("--version", action="version", version=f"THC4me {VERSION}")
    sub = p.add_subparsers(dest="cmd")

    scan = sub.add_parser("scan", help="Scan a file and output JSON")
    scan.add_argument("file")
    scan.add_argument("--out")
    scan.add_argument("--pretty", action="store_true")
    scan.set_defaults(func=cmd_scan)

    st = sub.add_parser("strings", help="Extract printable strings")
    st.add_argument("file")
    st.add_argument("--min-len", type=int, default=4)
    st.add_argument("--max-lines", type=int, default=20000)
    st.set_defaults(func=cmd_strings)

    imp = sub.add_parser("imports", help="List imported libraries/symbols")
    imp.add_argument("file")
    imp.set_defaults(func=cmd_imports)

    ent = sub.add_parser("entropy", help="Compute file entropy")
    ent.add_argument("file")
    ent.set_defaults(func=cmd_entropy)

    man = sub.add_parser("manifest", help="Dump AndroidManifest/Info.plist or list archive")
    man.add_argument("file")
    man.set_defaults(func=cmd_manifest)

    tools = sub.add_parser("tools", help="Show tool and library availability")
    tools.add_argument("--check", action="store_true")
    tools.set_defaults(func=cmd_tools)

    manu = sub.add_parser("manual", help="Show THC4me manual")
    manu.set_defaults(func=cmd_manual)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.cmd:
        parser.print_help(); sys.exit(1)
    args.func(args)

if __name__ == "__main__":
    main()
