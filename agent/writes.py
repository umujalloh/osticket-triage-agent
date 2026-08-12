import os

# No default: enabled by accident writes to real tickets, disabled by accident
# silently does nothing. Only true and false parse, so ENABLE_WRITES=yes fails
# loudly instead of reading as off.
_RAW = os.getenv("ENABLE_WRITES")
if _RAW is None:
    raise RuntimeError("ENABLE_WRITES is not set. Set it to true or false.")
if _RAW.strip().lower() not in ("true", "false"):
    raise RuntimeError(f"ENABLE_WRITES must be exactly true or false, got {_RAW!r}")

WRITES_ENABLED = _RAW.strip().lower() == "true"

def writes_enabled() -> bool:
    """Whether internal notes, priority changes, Slack posts and pages are
    permitted. Audit logging never consults this, so a ticket handled with
    writes off is still fully recorded in Splunk.
    """
    return WRITES_ENABLED
