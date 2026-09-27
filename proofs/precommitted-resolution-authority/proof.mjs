import { createHash } from "node:crypto";
import assert from "node:assert/strict";

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  return "{" + Object.keys(value).sort().map(k => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
}

function sha256(value) {
  return "sha256:" + createHash("sha256").update(
    typeof value === "string" ? value : canonical(value)
  ).digest("hex");
}

function deriveState(checks, originalTarget, effectiveTarget) {
  const required = checks.filter(c => c.required);
  if (required.some(c => c.outcome === "FAIL")) return "FAILED";
  if (required.some(c => c.outcome === "UNRESOLVED")) return "UNRESOLVED";
  if (required.every(c => c.outcome === "PASS")) {
    return effectiveTarget === originalTarget ? "SURVIVED" : "NARROWED";
  }
  throw new Error("invalid required-check set");
}

function projectChecks(checks) {
  return checks.map(({ id, requirement, required }) => ({ id, requirement, required }));
}

function validateResolution(r) {
  assert.equal(r.evidence.digest, EVIDENCE.digest);
  assert.equal(r.state, deriveState(r.checks, r.originalTarget, r.effectiveTarget));
  assert.match(r.authorityPolicyDigest, /^sha256:[0-9a-f]{64}$/);
  return true;
}

function matchesBoundary(boundary, resolution, actionPolicyDigest, actionId, predecessorState) {
  return (
    boundary.predecessorState === predecessorState &&
    boundary.subject === resolution.subject &&
    boundary.originalTarget === resolution.originalTarget &&
    boundary.authorityPolicyDigest === resolution.authorityPolicyDigest &&
    canonical(boundary.requiredChecks) === canonical(projectChecks(resolution.checks)) &&
    boundary.aggregationRule === "rlp-1-required-checks/v1" &&
    boundary.actionPolicyDigest === actionPolicyDigest &&
    boundary.permittedAction === actionId
  );
}

const EVIDENCE = {
  kind: "synthetic-native-evidence",
  digest: sha256("same independently valid evidence for both resolvers"),
};

const AUTHORITY_POLICY = {
  policy: "resolver-authority/v1",
  principals: ["did:example:resolver-a"],
  mode: "EXACT",
};

const ACTION_POLICY = {
  policy: "successor-action/v1",
  action: "advance",
  allowedStates: ["SURVIVED", "NARROWED"],
};

const CHECK_X = {
  id: "x",
  requirement: "require X",
  required: true,
  outcome: "PASS",
};

const CHECK_Y = {
  id: "y",
  requirement: "require Y",
  required: true,
  outcome: "PASS",
};

const CHECK_Z = {
  id: "z",
  requirement: "require Z",
  required: true,
  outcome: "PASS",
};

const predecessorState = sha256("authoritative predecessor state");

const boundary = {
  profile: "rlp-decision-boundary/v1",
  subject: "x402:lifecycle:1",
  originalTarget: "delivery satisfies promised specification",
  predecessorState,
  authorityPolicyDigest: sha256(AUTHORITY_POLICY),
  requiredChecks: projectChecks([CHECK_X, CHECK_Y]),
  aggregationRule: "rlp-1-required-checks/v1",
  actionPolicyDigest: sha256(ACTION_POLICY),
  permittedAction: "advance",
};

const resolverA = {
  subject: boundary.subject,
  originalTarget: boundary.originalTarget,
  effectiveTarget: boundary.originalTarget,
  evidence: EVIDENCE,
  authorityPolicyDigest: sha256(AUTHORITY_POLICY),
  checks: [CHECK_X, CHECK_Y],
};
resolverA.state = deriveState(
  resolverA.checks,
  resolverA.originalTarget,
  resolverA.effectiveTarget,
);

const resolverB = {
  subject: boundary.subject,
  originalTarget: boundary.originalTarget,
  effectiveTarget: boundary.originalTarget,
  evidence: EVIDENCE,
  authorityPolicyDigest: sha256(AUTHORITY_POLICY),
  checks: [CHECK_X, CHECK_Y, CHECK_Z],
};
resolverB.state = deriveState(
  resolverB.checks,
  resolverB.originalTarget,
  resolverB.effectiveTarget,
);

assert.equal(validateResolution(resolverA), true);
assert.equal(validateResolution(resolverB), true);

const actionPolicyDigest = sha256(ACTION_POLICY);

const aOperative = matchesBoundary(
  boundary,
  resolverA,
  actionPolicyDigest,
  "advance",
  predecessorState,
);
const bOperative = matchesBoundary(
  boundary,
  resolverB,
  actionPolicyDigest,
  "advance",
  predecessorState,
);

assert.equal(aOperative, true);
assert.equal(bOperative, false);

// Policy substitution after seeing evidence must also fail.
assert.equal(
  matchesBoundary(
    boundary,
    { ...resolverA, authorityPolicyDigest: sha256({ ...AUTHORITY_POLICY, principals: ["did:example:resolver-b"] }) },
    actionPolicyDigest,
    "advance",
    predecessorState,
  ),
  false,
);

assert.equal(
  matchesBoundary(
    boundary,
    resolverA,
    sha256({ ...ACTION_POLICY, allowedStates: ["FAILED"] }),
    "advance",
    predecessorState,
  ),
  false,
);

assert.equal(
  matchesBoundary(
    boundary,
    resolverA,
    actionPolicyDigest,
    "different-transition",
    predecessorState,
  ),
  false,
);

assert.equal(
  matchesBoundary(
    boundary,
    resolverA,
    actionPolicyDigest,
    "advance",
    sha256("different predecessor"),
  ),
  false,
);

console.log("same_evidence_digest=" + EVIDENCE.digest);
console.log("resolver_a_valid=true");
console.log("resolver_b_valid=true");
console.log("resolver_a_boundary_match=" + aOperative);
console.log("resolver_b_boundary_match=" + bOperative);
console.log("expected=only the precommitted resolver/check-set is transition-eligible");
console.log("result=PASS");
