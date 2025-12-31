from unv.classifier import classify
from unv.classifier import classify
from pathlib import Path
from unv.static_parser import analyze
import sys

MAX_FILES = 80
MAX_SIZE = 120 * 1024 * 1024

SKIP_DIRS = {
    "Xcode.app",
    "Simulator.app",
    "iOS Simulator.app",
    "Developer",
    "Command Line Tools"
}

VALID_SUFFIX = {".exe", ".bin", ".dylib", ".so"}

def tick(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()

def run(target):
    base = Path(target)
    results = []

    if base.is_file():
        tick(f"[ANALYZE] {base.name}")
        try:
            return analyze(str(base))
        except:
            return {}

    count = 0
    tick(f"[SCAN] {target}")

    for item in base.iterdir():
        if count >= MAX_FILES:
            break

        if item.name in SKIP_DIRS:
            continue

        if item.is_symlink():
            continue

        if item.is_file():
            if item.stat().st_size > MAX_SIZE:
                continue
            if item.suffix.lower() in VALID_SUFFIX:
                tick(f"[BIN] {item.name}")
                try:
                    results.append({"class": classify({"file": str(f if item.is_dir() else item), "analysis": analyze(str(f if item.is_dir() else item))}),
                        "file": str(item),
                        "analysis": analyze(str(item))
                    })
                    count += 1
                except:
                    pass

        if item.is_dir() and item.suffix.lower() == ".app":
            tick(f"[APP] {item.name}")
            binpath = item / "Contents/MacOS"
            if binpath.exists():
                for f in binpath.iterdir():
                    if f.stat().st_size > MAX_SIZE:
                        continue
                    tick(f"    └─ {f.name}")
                    try:
                        results.append({"class": classify({"file": str(f if item.is_dir() else item), "analysis": analyze(str(f if item.is_dir() else item))}),
                            "file": str(f),
                            "analysis": analyze(str(f))
                        })
                        count += 1
                    except:
                        pass
                    if count >= MAX_FILES:
                        break

    tick("[DONE]")
    return {
        "metadata": {"target": target},
        "files_analyzed": len(results),
        "results": results
    }
