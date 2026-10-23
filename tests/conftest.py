"""Shared fixtures: an in-process relay on ephemeral ports with a fake clock,
and NDJSON / sc2ref-backed test clients.

SPDX-License-Identifier: MIT
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY_DIR = os.path.dirname(HERE)
sys.path.insert(0, RELAY_DIR)
# sc2ref.py is vendored (see tests/vendor/README.md), so the suite stands alone.
sys.path.insert(0, os.path.join(HERE, "vendor"))
sys.path.insert(0, HERE)
