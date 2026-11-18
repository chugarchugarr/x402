# RLP-1 resolution lineage — pinned public reference

This is a **minimal public source snapshot** for review of [x402 PR #3291](https://github.com/x402-foundation/x402/pull/3291).

## Provenance

The source is extracted from the user's private repository `chugarchugarr/resolution-receipt-technocore` at pinned commit `2a2b11f905acd7a1d3dd430ff81ed279c350e6a4`. The original remains private and unchanged.

- `src/resolution_receipt/resolution.py`, `schema/resolution-state.schema.json`, and `tests/test_resolution_lineage.py` are copied **unchanged** from the pinned commit.
- `src/resolution_receipt/core.py` contains the original functions for canonical JSON, digesting, Ed25519 signatures, DIDs, and temporary test keys, extracted from the same commit. Unrelated Technocore and task-receipt functions were excluded.
- No private policy, credentials, release artifacts, signed production records, or other private project materials are included.

## Reproduce

Requires Python 3.11+ and `cryptography>=42`.

From the `rlp1-reference` directory:

```sh
python -m pip install -r requirements.txt
PYTHONPATH=src python -m unittest discover -s tests -p 'test_*.py' -v
```

The eleven included tests cover all four derived states, known evidence references, rejection of zero required checks, signing, rejection of a falsely declared state, append-only correction, history rewriting, and subject continuity.

## Boundary

This is an **experimental application-layer reference**, not an approved x402 extension, payment proof, or authority grant. A valid signature proves integrity and key control, **not** truth, evidence completeness, or authorization to act.

The low-level `derive_resolution_state` helper assumes that checks have already been validated; `build_resolution_payload` enforces at least one required check. Native evidence must still be verified according to its own format.

MIT license. No private repositories were made public to create this snapshot.

All included lineage tests run locally without contacting x402 services or requiring access to the private source repository.
