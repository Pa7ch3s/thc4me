#!/usr/bin/env python3
"""
unv_static_parser.py
Static parser module for THC4me backend.

Functions:
- analyze(path) -> dict with keys: artifacts[], findings[]

Intended to be imported and called by unv.cli.py or unv.daemon.py.
"""

import os
import re
import json
import math
import hashlib
from pathlib import Path
from typing import List, Dict, Any

# optional imports
try:
    import lief
except Exception as e:
    lief = None

try:
    import pefile
except Exception:
    pefile = None

# quick secret regex (tune as needed)
CREDS_RE = re.compile(
    r"(?i)(?:api[_-]?key|apikey|password|pass|secret|token|auth[_-]?key|client_secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})['\"]?"
)

# printable string extractor (binary-safe)
def extract_strings_bytes(b: bytes, min_len: int = 4, max_strings: int = 100_000) -> List[str]:
    res = []
    cur = []
    for c in b:
        if 32 <= c < 127:
            cur.append(chr(c))
        else:
            if len(cur) >= min_len:
                res.append(''.join(cur))
                if len(res) >= max_strings:
                    return res
            cur = []
    if len(cur) >= min_len and len(res) < max_strings:
        res.append(''.join(cur))
    return res

def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    occ = {}
    for b in data:
        occ[b] = occ.get(b, 0) + 1
    ent = 0.0
    length = len(data)
    for v in occ.values():
        p = v / length
        ent -= p * math.log2(p)
    return ent

def safe_lief_parse(path: str):
    if not lief:
        return None, "lief-not-installed"
    try:
        return lief.parse(path), None
    except Exception as e:
        return None, str(e)

def analyze_pe_with_pefile(path: str) -> Dict[str, Any]:
    out = {"pe": {}, "certs": []}
    if not pefile:
        out["pe"]["error"] = "pefile-not-installed"
        return out
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        ])
        out["pe"]["entrypoint"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(pe, "OPTIONAL_HEADER") else ""
        out["pe"]["imports"] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                out["pe"]["imports"].append({"dll": imp.dll.decode(errors="ignore") if isinstance(imp.dll, bytes) else str(imp.dll),
                                             "symbols": [i.name.decode(errors="ignore") if i.name else "" for i in imp.imports]})
        out["pe"]["exports"] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                out["pe"]["exports"].append(e.name.decode(errors="ignore") if e.name else "")
        # certificates (WIN_CERTIFICATE) extraction attempt
        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and pe.DIRECTORY_ENTRY_SECURITY:
            for sec in pe.DIRECTORY_ENTRY_SECURITY:
                # sec.struct contains Certificate structure
                try:
                    cert_blob = sec.struct['Certificate'].rstrip(b'\x00')
                    out["certs"].append(cert_blob.decode(errors="ignore")[:2000])
                except Exception:
                    # fallback: dump as raw hex
                    try:
                        out["certs"].append(str(sec.struct))
                    except Exception:
                        pass
    except Exception as e:
        out["pe"]["error"] = str(e)
    return out

def analyze(path: str, max_string_sample: int = 5000) -> Dict[str, Any]:
    """
    Perform static analysis. Return dict:
    {
      "artifacts": [ {type,name,value,detail,evidence_path}, ... ],
      "findings": [ {code,title,severity,confidence,description,evidence}, ... ]
    }
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)

    artifacts = []
    findings = []
    file_bytes = p.read_bytes()
    sha = sha256_of_file(path)
    size = p.stat().st_size

    artifacts.append({"type":"metadata","name":"filename","value":p.name,"detail":f"size={size} sha256={sha}","evidence_path":path})

    # try lief parse for headers, imports, sections
    lief_obj, lief_err = safe_lief_parse(path)
    if lief_obj:
        try:
            fmt = lief_obj.format.name if hasattr(lief_obj, "format") else str(type(lief_obj))
            artifacts.append({"type":"binary_format","name":"format","value":fmt,"detail":"","evidence_path":path})
            # sections
            try:
                secs = []
                for s in lief_obj.sections:
                    sec_info = {"name": s.name, "size": s.size, "vsize": getattr(s, "virtual_size", None), "entropy": entropy(s.content if hasattr(s,"content") else b"")}
                    secs.append(sec_info)
                artifacts.append({"type":"sections","name":"sections_summary","value":json.dumps(secs),"detail":f"count={len(secs)}","evidence_path":path})
            except Exception:
                pass
            # imports / symbols
            try:
                imports = []
                for imported in lief_obj.imports:
                    imports.append({"name": imported.name, "entries": [e.name for e in imported.entries]})
                artifacts.append({"type":"imports","name":"imports_list","value":json.dumps(imports[:200]),"detail":f"imports_count={len(imports)}","evidence_path":path})
            except Exception:
                pass
            # exports
            try:
                exports = [e.name for e in getattr(lief_obj, "exported_functions", [])]
                artifacts.append({"type":"exports","name":"exports_list","value":json.dumps(exports[:200]),"detail":f"export_count={len(exports)}","evidence_path":path})
            except Exception:
                pass
        except Exception:
            artifacts.append({"type":"error","name":"lief_parse_failed","value":lief_err,"detail":"","evidence_path":path})
    else:
        artifacts.append({"type":"note","name":"lief_unavailable_or_failed","value":lief_err,"detail":"lief parse failed or not installed","evidence_path":path})

    # PE extra analysis
    if p.suffix.lower() in (".exe", ".dll", ".sys", ".ocx") or (pefile is not None):
        pe_info = analyze_pe_with_pefile(path)
        if pe_info.get("pe"):
            artifacts.append({"type":"pe_info","name":"pe_summary","value":json.dumps(pe_info.get("pe", {})),"detail":"","evidence_path":path})
        if pe_info.get("certs"):
            for i, c in enumerate(pe_info["certs"]):
                artifacts.append({"type":"certificate","name":f"pe_cert_{i}","value":c[:2000],"detail":"embedded certificate (truncated)","evidence_path":path})

    # strings extraction
    strings = extract_strings_bytes(file_bytes, min_len=4, max_strings=20000)
    if strings:
        artifacts.append({"type":"strings_sample","name":"strings_top_sample","value":"\n".join(strings[:max_string_sample]),"detail":f"total_strings={len(strings)}","evidence_path":path})

    # heuristic: high entropy sections or file-level entropy
    ent = entropy(file_bytes)
    artifacts.append({"type":"entropy","name":"file_entropy","value":str(ent),"detail":"Shannon entropy of file bytes","evidence_path":path})
    if ent > 7.5:
        findings.append({
            "code":"TC-HIGH-ENTROPY",
            "title":"High entropy blob (possible packing/encryption)",
            "severity":"Medium",
            "confidence":"Tentative",
            "description":f"File entropy {ent:.2f} suggests packed or encrypted content. Manual review recommended.",
            "evidence":f"entropy={ent:.2f}"
        })

    # secret regex scans in strings (dedupe)
    seen_keys = set()
    for s in strings[:10000]:
        m = CREDS_RE.search(s)
        if m:
            key = m.group(1)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append({
                "code":"TC-HARDCODED-CREDS",
                "title":"Hard-coded credential (static)",
                "severity":"High",
                "confidence":"Firm",
                "description":"Detected probable hard-coded credential or token in binary strings.",
                "evidence": s.strip()
            })
            artifacts.append({"type":"strings_match","name":"hardcoded_cred","value":key,"detail":s.strip(),"evidence_path":path})
            if len(seen_keys) >= 25:
                break

    # import/export heuristics
    # if a binary imports many networking functions flag low-medium finding
    net_funcs = ["send","recv","connect","gethostbyname","WSAStartup","socket","curl_easy_perform","URLDownloadToFile"]
    import_text = ""
    try:
        import_text = json.loads(artifacts[-1]["value"]) if artifacts and artifacts[-1]["type"] == "imports" else ""
    except Exception:
        import_text = ""
    imported_names = []
    if isinstance(import_text, list):
        for imp in import_text:
            for e in imp.get("entries", []):
                if isinstance(e, str):
                    imported_names.append(e)
    else:
        # fallback search on strings
        for f in net_funcs:
            for s in strings[:2000]:
                if f in s:
                    imported_names.append(f)
                    break
    if imported_names:
        # small heuristic
        if any(x in imported_names for x in net_funcs):
            findings.append({
                "code":"TC-NETWORK-IO",
                "title":"Network I/O usage detected",
                "severity":"Low",
                "confidence":"Firm",
                "description":"Binary appears to reference network IO routines. Thick clients often contact remote services.",
                "evidence":",".join(set(imported_names)[:10])
            })

    result = {"artifacts": artifacts, "findings": findings, "meta": {"sha256": sha, "size": size}}
    return result

# CLI test harness if called directly
if __name__ == "__main__":
    import argparse, sys
    p = argparse.ArgumentParser()
    p.add_argument("file", help="file to analyze")
    p.add_argument("--pretty", action="store_true")
    args = p.parse_args()
    out = analyze(args.file)
    if args.pretty:
        print(json.dumps(out, indent=2))
    else:
        print(json.dumps(out))
