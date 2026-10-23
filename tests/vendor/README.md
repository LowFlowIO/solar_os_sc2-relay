# Vendored from the SolarOS client repository

`sc2ref.py` is a verbatim copy of `protocol/sc2/tools/sc2ref.py` and
`../data/sc2_vectors.json` of `protocol/sc2/vectors/sc2_vectors.json`, taken
from the SolarOS client repository (LowFlowIO/solar_os). They let the
relay's pytest suite run standalone, without the firmware tree.

When the client's protocol or vectors change (`gen_vectors.py` rewrites the
JSON), copy both files here again.
