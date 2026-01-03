from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter
import json

def pretty(data, quiet=False):
    if quiet:
        return

    try:
        payload = json.dumps(data, indent=2)
    except Exception:
        payload = str(data)

    print(highlight(payload, JsonLexer(), TerminalFormatter()))
