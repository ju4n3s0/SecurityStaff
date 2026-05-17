import json
try:
    json.loads('\n  "risk_level"')
except json.JSONDecodeError as e:
    print("Exception:", e)
    print("Str:", str(e))
    print("Repr:", repr(str(e)))