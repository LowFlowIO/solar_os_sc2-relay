"""python -m sc2_relay [--env-file FILE] [--check-config] [--print-config]

SPDX-License-Identifier: MIT
"""

import argparse
import asyncio
import json
import logging
import os
import sys

from . import __version__
from .config import Config, ConfigError


def load_env_file(path):
    """KEY=VALUE lines; # comments; values may be quoted. Existing
    environment variables win, so docker/compose overrides keep working."""
    out = {}
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:]
            k, sep, v = line.partition("=")
            if not sep:
                raise ConfigError("%s:%d: expected KEY=VALUE" % (path, n))
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[k.strip()] = v
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sc2_relay", description="SC2 reference relay " + __version__)
    ap.add_argument("--env-file", help="read SC2_* settings from this file (environment overrides it)")
    ap.add_argument("--check-config", action="store_true", help="validate the configuration and exit")
    ap.add_argument("--print-config", action="store_true", help="print the effective (non-secret) configuration")
    args = ap.parse_args(argv)
    env = {}
    if args.env_file:
        env.update(load_env_file(args.env_file))
    env.update({k: v for k, v in os.environ.items() if k.startswith("SC2_")})
    try:
        config = Config.from_env(env)
    except ConfigError as e:
        print("configuration error: %s" % e, file=sys.stderr)
        return 2
    logging.basicConfig(level=getattr(logging, config.log_level, logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.print_config or args.check_config:
        print(json.dumps(config.summary(), indent=2, sort_keys=True))
        if args.check_config:
            return 0
    from .server import run
    try:
        asyncio.run(run(config))
    except (RuntimeError, OSError) as e:
        logging.getLogger("sc2_relay").error("%s", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
