# Precommitted resolution-authority counterexample

This is a minimal executable reproduction of the Resolver A / Resolver B boundary discussed in x402 issue #2833.

It isolates one question:

> If two internally valid resolutions consume the same independently valid evidence, what prevents a party from choosing the resolver/check-set after seeing the evidence?

The proof commits the decision boundary in predecessor state before resolution:

- subject;
- original target;
- resolver-authority policy digest;
- required check definitions;
- aggregation rule;
- action-policy digest; and
- permitted transition.

Then it evaluates two resolutions over the exact same evidence:

```text
Resolver A -> checks X + Y
Resolver B -> checks X + Y + Z
```

Both pass the resolution-validity function. Only Resolver A matches the predecessor commitment.

Run:

```bash
node proof.mjs
```

Expected tail:

```text
resolver_a_valid=true
resolver_b_valid=true
resolver_a_boundary_match=true
resolver_b_boundary_match=false
expected=only the precommitted resolver/check-set is transition-eligible
result=PASS
```

The script also rejects post-evidence substitution of the authority policy, action policy, permitted transition, and predecessor-state reference.

## Invariant

```text
valid evidence != valid resolution != authorized transition
```

The selector for operative authority is not the evidence. It is the already-authoritative predecessor-state commitment.

## Scope

This is a falsifier for policy-selection retroactivity. It does not claim that a hash or signature creates institutional authority, nor does it replace native x402 evidence, delivery receipts, settlement facts, verifier receipts, or dispute mechanisms.

The application/contract layer still has to establish that the predecessor state and its committing principal were authoritative and that the commitment existed before the relevant evidence could influence selection.

This branch is intentionally separate from PR #3291. RLP-1 remains the append-only resolution-lineage layer; this proof demonstrates the authority condition that must hold before a resolution is allowed to become operative.
