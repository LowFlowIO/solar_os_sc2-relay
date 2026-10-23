"""Host interop test: the C protocol/sc2 core and the SolarOS SC2 engine,
built with gcc into a small harness, talk to this Python relay over TCP.
Skipped when gcc is not available.

SPDX-License-Identifier: MIT
"""

import asyncio
import os
import shutil
import subprocess

import pytest

from helpers import relay_server, run

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
SC2 = os.path.join(REPO, "protocol", "sc2")
ED = os.path.join(REPO, "src", "vendor", "meshcore", "ed25519")
WG = os.path.join(REPO, "components", "wireguard_lwip", "src")
SVC = os.path.join(REPO, "src", "services")

pytestmark = pytest.mark.skipif(shutil.which(os.environ.get("CC", "gcc")) is None, reason="no C compiler")


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    cc = os.environ.get("CC", "gcc")
    out = tmp_path_factory.mktemp("c")
    inc = ["-I" + os.path.join(SC2, "include"), "-I" + ED, "-I" + os.path.join(WG, "crypto", "refc"), "-I" + WG,
           "-I" + SVC]
    vendor = [os.path.join(ED, f) for f in ("fe.c", "ge.c", "sc.c", "sha512.c")] + \
             [os.path.join(WG, "crypto", "refc", f) for f in ("x25519.c", "chacha20.c", "chacha20poly1305.c",
                                                              "poly1305-donna.c")] + [os.path.join(WG, "crypto.c")]
    objs = []
    for i, src in enumerate(vendor):
        o = str(out / ("v%d.o" % i))
        subprocess.run([cc, "-std=c11", "-O2", "-w"] + inc + ["-c", src, "-o", o], check=True)
        objs.append(o)
    core = sorted(os.path.join(SC2, "src", f) for f in os.listdir(os.path.join(SC2, "src")) if f.endswith(".c"))
    eng = [os.path.join(SVC, "solar_os_sc2_engine.c"), os.path.join(SVC, "solar_os_sc2_selftest.c")]
    exe = str(out / "sc2_relay_c_client")
    r = subprocess.run([cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"] + inc +
                       [os.path.join(HERE, "c", "sc2_relay_c_client.c")] + core + eng + objs + ["-o", exe],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return exe


def test_c_engine_against_python_relay(harness):
    async def body():
        async with relay_server(relay_id="relay.c-interop") as srv:
            proc = await asyncio.create_subprocess_exec(harness, "127.0.0.1", str(srv.ports["plain"]),
                                                        "relay.c-interop", stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(proc.communicate(), 60)
            assert proc.returncode == 0, err.decode()
            assert out.decode().strip() == "SC2-C-RELAY OK"
            st = srv.relay.store
            assert st.scalar("SELECT COUNT(*) FROM public_log") == 1
            assert st.scalar("SELECT COUNT(*) FROM room_log WHERE kind='msg'") == 2
            # nothing the relay stored contains the private plaintexts
            dump = "\n".join("\n".join(str(v) for v in row) for t in ("inbox", "room_log")
                             for row in st.all("SELECT * FROM " + t))
            assert "hello from C" not in dump and "sealed room message" not in dump
    run(body())
