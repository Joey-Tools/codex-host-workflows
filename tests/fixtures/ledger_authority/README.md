# Frozen ledger authority fixture

This directory contains the exact validator and case schema bytes from
`Joey-Tools/codex-skill-friction-ledger` used by the host state helper's
single-repository conformance gate. `manifest.json` pins every copied file by
SHA-256, so CI neither discovers nor trusts an adjacent checkout.

Refresh this fixture only when the ledger authority changes, and update the
host conformance vectors in the same change.
