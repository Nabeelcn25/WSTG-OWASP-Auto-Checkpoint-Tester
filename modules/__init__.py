# modules/__init__.py

# Expose the info dispatcher so `from modules import info` works
from . import info  # noqa: F401

# The following subpackages are available if you later want to import them
# directly from `modules`, e.g. `from modules import conf`:
from . import auth      # noqa: F401
from . import authz     # noqa: F401
from . import conf      # noqa: F401
from . import idnt      # noqa: F401
from . import info as _info_pkg  # keep reference to the package if needed
