from pathlib import Path

def classify(entry):
    p = entry["file"]
    imports = entry["analysis"]["imports"][0]["imports"]

    tags = []

    if any("@rpath/Electron" in i for i in imports):
        tags.append("ELECTRON_PRELOAD_RCE")

    if any("QtCore.framework" in i for i in imports):
        tags.append("QT_PLUGIN_RPATH_HIJACK")

    if any("crashpad" in p.lower() or "helper" in p.lower() for _ in [0]):
        tags.append("HELPER_BRIDGE")

    if any(i.startswith("@executable_path") for i in imports):
        tags.append("RELATIVE_RPATH_PIVOT")

    if entry["analysis"]["entropy"] > 6.9:
        tags.append("PACKED_OR_PROTECTED")

    return ",".join(tags) if tags else "NATIVE"
