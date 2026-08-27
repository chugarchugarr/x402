# Extension: `resolution-lineage`

## Summary

`resolution-lineage` is an optional application-layer composition profile for recording how independently verifiable evidence changes an operative conclusion over time.

It does not define a new payment receipt, delivery proof, verifier verdict format, operation binding, settlement mechanism, dispute mechanism, anchoring mechanism, or reputation system.

The profile composes existing artifacts and preserves three properties:

1. independently verifiable artifacts that disagree on the same subject remain separately addressable;
2. their effect on the operative conclusion is represented as a resolution state;
3. corrections and narrowed successor conclusions append new records instead of mutating earlier signed conclusions.

## Scope

This profile operates above existing x402 evidence.

A resolution implementation MAY consume artifacts including:

- operation-bound evidence such as an `operationDigest`;
- signed Offer/Receipt artifacts;
- delivery-receipt artifacts;
- SAR or other independently verifiable verifier receipts;
- settlement or application evidence defined elsewhere.

Those native artifacts remain authoritative for their own semantics.

A `resolution-lineage` implementation MUST NOT reinterpret a native verifier artifact as valid without first verifying it according to that artifact's native verification rules.

## Non-goals

This profile does not define:

- `PASS`, `FAIL`, `INDETERMINATE`, or another verifier verdict vocabulary;
- delivery success or failure semantics;
- settlement verification;
- request or response hashing;
- signer authorization;
- evidence anchoring;
- generic dispute submission or counter-evidence;
- verifier selection or trust policy;
- completeness of an evidence set.

## Resolution record

A resolution record has the following logical shape:

```json
{
  "version": "resolution-lineage/1",
  "subjectDigest": "sha256:...",
  "state": "SURVIVED",
  "verifierArtifacts": [
    {
      "format": "sar/0.1",
      "artifactDigest": "sha256:..."
    }
  ],
  "previousResolutionId": null,
  "supersedesResolutionId": null,
  "supersedesSubjectDigest": null,
  "reason": "Initial independently verifiable evidence supports the subject.",
  "issuedAt": "2026-08-27T00:00:00Z"
}
```

`artifactDigest` identifies the native verifier artifact. The artifact itself remains subject to its native schema, signature, trust-root, and verification rules.

The profile does not define a replacement verifier envelope.

## Resolution states

### `SURVIVED`

The current subject remains operative after the resolver evaluates the accepted evidence set.

`SURVIVED` is not equivalent to a native verifier `PASS`. It describes the current status of the subject after resolution.

### `UNRESOLVED`

The resolver cannot preserve or reject the current subject conclusively.

A common cause is the presence of independently verifiable artifacts that address the same subject and reach materially conflicting native conclusions.

Implementations MUST preserve the conflicting artifact references separately.

They MUST NOT replace those artifacts with only a synthetic conflict verdict.

### `NARROWED`

The earlier subject no longer survives at its original scope, but a strictly narrower successor subject is supported.

A `NARROWED` record MUST identify the superseded subject through `supersedesSubjectDigest`.

The successor subject MUST have its own digest.

### `FAILED`

The current subject no longer survives the accepted evidence set.

`FAILED` describes the resolution state of the subject. It does not replace or alter the verdict contained in any underlying native verifier artifact.

## Disagreement

Two verifier artifacts constitute disagreement for this profile only when:

1. both artifacts verify successfully under their native formats;
2. they address the same subject;
3. they are attributable to distinct verifier identities under those native formats; and
4. their native conclusions materially conflict.

The resolution layer MUST NOT manufacture independence merely because two artifact objects exist.

## Supersession

Corrections are append-only.

A successor resolution MAY carry:

```text
previousResolutionId
supersedesResolutionId
supersedesSubjectDigest
```

`previousResolutionId` identifies lineage order.

`supersedesResolutionId` identifies the earlier operative resolution replaced by the successor.

`supersedesSubjectDigest` identifies the earlier subject when the successor changes or narrows the claim itself.

An implementation MUST NOT represent a correction by editing the historical resolution in place.

Earlier valid records remain valid historical evidence after supersession.

Supersession changes which resolution is operative. It does not rewrite what was previously concluded.

## Example

Given two independently signed SAR v0.1 receipts addressing the same `task_id_hash`:

```text
Verifier A: PASS / SPEC_MATCH
Verifier B: FAIL / SPEC_MISMATCH
```

both native receipts first verify under SAR.

A resolution lineage may then record:

```text
SAR(A, PASS, subject=S)
  -> SURVIVED
SAR(A, PASS, subject=S)
+ SAR(B, FAIL, subject=S)
  -> UNRESOLVED
```

If later independently verifiable evidence supports only a narrower successor subject `S'`:

```text
S -> superseded
S' -> NARROWED
```

The earlier `SURVIVED` and `UNRESOLVED` records remain addressable and unmodified.

## Relationship to existing x402 work

This profile is intended to compose with, rather than replace:

- Offer/Receipt;
- operation binding discussed in #1921;
- Settlement Attestation Receipt (SAR) in #1195;
- delivery-receipt work in #2833;
- correctness/dispute work in #2887.

The profile deliberately leaves payment, delivery, verifier, and dispute semantics in those respective layers.

Its only concern is preservation of independently verifiable disagreement and append-only evolution of the conclusion drawn from that evidence.

## Reference implementation

Reference proof:

https://github.com/chugarchugarr/-x402-resolution-receipt

The fixture verifies native SAR-v0.1-conformant Ed25519-signed test receipts before resolution processing and includes negative controls for native receipt tampering and historical resolution mutation.

The fixture keys are independent test verifier keys. They are not production Default Settlement Verifier identities.

## Security considerations

A resolution record does not prove that its evidence set is complete.

A resolver can omit evidence unless an external completeness mechanism prevents or exposes omission.

Distinct signatures do not automatically establish institutional or economic independence. Independence MUST be established through the native verifier identities and the trust policy applied by the consumer.

Supersession provides historical preservation, not objective correctness. Consumers remain responsible for deciding which evidence sources and resolver authorities they trust.
