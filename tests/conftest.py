"""Shared fixtures: an in-process relay on ephemeral ports with a fake clock,
and NDJSON / sc2ref-backed test clients.

SPDX-License-Identifier: MIT
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY_DIR = os.path.dirname(HERE)
REPO = os.path.dirname(RELAY_DIR)
sys.path.insert(0, RELAY_DIR)
sys.path.insert(0, os.path.join(REPO, "protocol", "sc2", "tools"))
sys.path.insert(0, HERE)
