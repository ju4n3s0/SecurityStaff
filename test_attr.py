class Dummy:
    pass
d = Dummy()
try:
    d.get("risk_level")
except AttributeError as e:
    print("Exception:", e)
    print("Str:", str(e))
    print("Repr:", repr(str(e)))