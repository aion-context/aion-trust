#!/usr/bin/env python3
"""
Executable proof of the aion-trust Phase-7 "issuer-committed reliance" design.

Each panel finding becomes a runnable hypothesis. We model the mechanism with real
domain-separated, length-prefixed BLAKE2b hashing + a Merkle commitment, and an HMAC
keyed-hash as a stand-in for the issuer's Ed25519 signature (the design logic only needs
"only the key holder can produce valid bytes over this message"). Hypotheses assert the
design's claims; a wrong fix makes an assertion FAIL — the empirical analogue of a panel
blocker. NOT the real crypto (that's aion-context Ed25519/BLAKE3); this proves the LOGIC.
"""
import hashlib, hmac

# ---- domain-separated, length-prefixed hashing (models rivest NEW-1/NEW-2) ----
def H(*parts):
    h = hashlib.blake2b()
    for p in parts:
        if isinstance(p, str): p = p.encode()
        elif isinstance(p, int): p = p.to_bytes(8, "big")
        h.update(len(p).to_bytes(4, "big")); h.update(p)   # length-prefix => no concat ambiguity
    return h.hexdigest()

DOM_CLAIM = "aion-trust/claim/v1"
DOM_LEAF  = "aion-trust/reliance-leaf/v1"
DOM_KIND  = "aion-trust/reliance-kind/v1"
DOM_NODE  = "aion-trust/merkle-node/v1"
EMPTY_ROOT = H("aion-trust/empty-reliance/v1")

# ---- Merkle over ordered leaves (duplicate-last for odd counts) ----
def _levels(leaves):
    levels = [leaves[:]]; lvl = leaves[:]
    while len(lvl) > 1:
        nxt = [H(DOM_NODE, lvl[i], lvl[i+1] if i+1 < len(lvl) else lvl[i]) for i in range(0, len(lvl), 2)]
        levels.append(nxt); lvl = nxt
    return levels
def root_of(leaves): return _levels(leaves)[-1][0] if leaves else EMPTY_ROOT
def proof_of(leaves, index):
    path = []; idx = index
    for lvl in _levels(leaves)[:-1]:
        sib = idx ^ 1
        path.append(lvl[sib] if sib < len(lvl) else lvl[idx])
        idx //= 2
    return path
def verify_leaf(leaf, index, path, root):
    node = leaf; idx = index
    for sib in path:
        node = H(DOM_NODE, node, sib) if idx % 2 == 0 else H(DOM_NODE, sib, node)
        idx //= 2
    return node == root

# ---- reliance leaves (per-index salt, kind as a separate sub-commitment: saltzer N1 / rivest NEW-2) ----
def kind_commit(kind, kind_salt): return H(DOM_KIND, kind_salt, kind)
def leaf_hash(index, salt, from_claim_id, kcommit): return H(DOM_LEAF, index, salt, from_claim_id, kcommit)

# ---- signature stand-in: only the issuer key produces valid bytes over the canonical message ----
def canon_claim(c):
    return H(DOM_CLAIM, c["subject_id"], c["schema_id"], c["body_root"], c["field_count"],
             c["reliance_root"], c["reliance_count"], c["validity"], c["claim_id"])
def sign(key, msg):  return hmac.new(key, msg.encode(), hashlib.blake2b).hexdigest()
def sig_ok(key, msg, sig): return hmac.compare_digest(sign(key, msg), sig)

def issue(issuer_id, issuer_key, subject_id, schema_id, body_root, field_count, validity,
          reliance_targets, master_salt):
    leaves, meta = [], []
    for i, (fcid, kind) in enumerate(reliance_targets):
        salt_i    = H("reliance-salt", master_salt, i)
        kind_salt = H("reliance-kind-salt", master_salt, i)
        kc        = kind_commit(kind, kind_salt)
        leaves.append(leaf_hash(i, salt_i, fcid, kc))
        meta.append({"index": i, "salt": salt_i, "from_claim_id": fcid,
                     "kind_commit": kc, "kind": kind, "kind_salt": kind_salt})
    # NEW-A / rivest NEW-5: claim_id is a HIDING commitment (folds master_salt) — not a bare body digest
    claim_id = H("claim-id", master_salt, subject_id, schema_id, body_root)
    c = {"issuer_id": issuer_id, "subject_id": subject_id, "schema_id": schema_id,
         "body_root": body_root, "field_count": field_count,
         "reliance_root": root_of(leaves), "reliance_count": len(leaves),   # NEW-4: mandatory & signed
         "validity": validity, "claim_id": claim_id}
    c["issuer_signature"] = sign(issuer_key, canon_claim(c))
    return c, meta, leaves

def disclose(meta, leaves, open_kind=False):
    out = []
    for m in meta:
        d = {"index": m["index"], "salt": m["salt"], "from_claim_id": m["from_claim_id"],
             "kind_commit": m["kind_commit"], "audit_path": proof_of(leaves, m["index"])}
        if open_kind: d["kind"], d["kind_salt"] = m["kind"], m["kind_salt"]
        out.append(d)
    return out

# ---- verifier: authenticity -> claim revocation -> FIFTH CHECK (reliance), all at verifier epoch e_v ----
def verify(claim, disclosed, ledger, registry, e_v):
    ikey = registry.get(claim["issuer_id"])
    if ikey is None: return ("REJECT", "unknown issuer")
    if not sig_ok(ikey, canon_claim(claim), claim["issuer_signature"]):
        return ("REJECT", "bad signature")                              # H3/H4: strip/inject caught here
    st = ledger.get(claim["claim_id"])
    if st and st["status"] == "revoked" and st["epoch"] <= e_v:
        return ("REJECT", "claim revoked")
    count, root = claim["reliance_count"], claim["reliance_root"]
    if count == 0:
        return ("ACCEPT", "no reliance") if root == EMPTY_ROOT else ("REJECT", "count0/nonempty root")
    if sorted(l["index"] for l in disclosed) != list(range(count)):
        return ("AMBER", "incomplete reliance disclosure")              # H1/H7: omission/dup caught
    for l in disclosed:
        kc = l["kind_commit"]
        if l.get("kind") is not None and kc != kind_commit(l["kind"], l["kind_salt"]):
            return ("REJECT", "kind sub-commitment mismatch")
        if not verify_leaf(leaf_hash(l["index"], l["salt"], l["from_claim_id"], kc),
                           l["index"], l["audit_path"], root):
            return ("REJECT", "reliance leaf not in root")              # H7: swap/dup caught
        us = ledger.get(l["from_claim_id"])
        if us and us["status"] == "revoked" and us["epoch"] <= e_v:
            return ("REJECT", "relied-upon claim revoked")             # H2/H5: transitive revocation
    return ("ACCEPT", "reliance intact")

# ====================== SCENARIO ======================
K_ID, K_BG, K_EVIL = b"identity-provider-key", b"bg-provider-key", b"attacker-key"
registry = {"did:idp": K_ID, "did:bg": K_BG}          # public keys; attacker not trusted for anyone
MS_A, MS_B = "master-salt-A", "master-salt-B"

A, _, _        = issue("did:idp", K_ID, "did:subj", "identity/v1", "bodyA", 3, "2026..null", [], MS_A)
B, mB, lB      = issue("did:bg", K_BG, "did:subj", "background_check/v1", "bodyB", 6,
                       "2026..null", [(A["claim_id"], "identity_basis")], MS_B)
ledger = {A["claim_id"]: {"status": "issued", "epoch": 10},
          B["claim_id"]: {"status": "issued", "epoch": 10}}

def result(*a): return verify(*a)[0]
tests = []
def check(name, cond, detail=""): tests.append((name, cond, detail))

# H0 baseline: honest present-and-verify accepts
check("H0 baseline accept", result(B, disclose(mB, lB), ledger, registry, 20) == "ACCEPT")

# H1 (rivest F5 / omission): drop the disclosed reliance leaf -> not ACCEPT
check("H1 omission detected", result(B, [], ledger, registry, 20) != "ACCEPT",
      "count=1 but zero leaves disclosed")

# H2 (lamport INV-2 / fifth check): revoke upstream A@19 -> B fails at e_v>=19, ok at e_v<19
led2 = dict(ledger); led2[A["claim_id"]] = {"status": "revoked", "epoch": 19}
check("H2 transitive fail-closed", result(B, disclose(mB, lB), led2, registry, 20) == "REJECT")
check("H2 pre-revocation still ok", result(B, disclose(mB, lB), led2, registry, 15) == "ACCEPT")

# H3 (rivest F2 / reliance injection): attacker forges a malicious reliance_root, re-signs w/ own key
Binj = dict(B); Binj["reliance_root"] = H("evil-root"); Binj["issuer_signature"] = sign(K_EVIL, canon_claim(Binj))
check("H3 injection rejected", result(Binj, [], led2, registry, 20) == "REJECT",
      "verifier uses B's real issuer key (did:bg) from registry, not the attacker's")

# H4 (rivest NEW-4 / strip): flip reliance to count=0 but keep the original signature (signed over count=1)
Bstrip = dict(B); Bstrip["reliance_count"] = 0; Bstrip["reliance_root"] = EMPTY_ROOT  # signature NOT re-made
check("H4 strip-to-no-reliance rejected", result(Bstrip, [], led2, registry, 20) == "REJECT",
      "canonical bytes now differ -> signature invalid")

# H5 (lamport NEW-B / e_v pinning): the epoch is the VERIFIER's; a subject cannot pick a stale one.
# There is no subject-epoch input to verify(); the verifier's own e_v=20 catches the epoch-19 revocation.
check("H5 verifier controls e_v", result(B, disclose(mB, lB), led2, registry, 20) == "REJECT",
      "no presentation field can move e_v below the revocation epoch")

# H6 (saltzer F1-F4 / no PII, no graph on ledger): ledger entries carry ONLY {status,epoch}
led_keys = set(k for e in ledger.values() for k in e.keys())
check("H6 ledger has no reliance topology", led_keys == {"status", "epoch"},
      f"ledger value keys = {sorted(led_keys)} (no from/to/kind edge)")

# H7 (rivest NEW-2 / index binding): a 2-target claim; duplicate leaf0 as a fake leaf1 -> rejected
C, mC, lC = issue("did:bg", K_BG, "did:subj", "background_check/v1", "bodyC", 6, "2026..null",
                  [(A["claim_id"], "identity_basis"), ("did:otherclaim", "prior_check")], MS_B)
dup = disclose(mC, lC)
dup[1] = {**dup[1], "salt": dup[0]["salt"], "from_claim_id": dup[0]["from_claim_id"],
          "kind_commit": dup[0]["kind_commit"], "audit_path": dup[0]["audit_path"]}  # forge index1 = copy of leaf0
led3 = dict(ledger); led3[C["claim_id"]] = {"status": "issued", "epoch": 10}
check("H7 leaf duplication rejected", verify(C, dup, led3, registry, 20)[0] == "REJECT",
      "forged leaf1 does not recompute reliance_root")

# H8 (NEW-A / hiding claim_id): identical body, different master_salt -> different claim_id (not confirmable)
A2, _, _ = issue("did:idp", K_ID, "did:subj", "identity/v1", "bodyA", 3, "2026..null", [], "different-salt")
check("H8 claim_id is a hiding commitment", A["claim_id"] != A2["claim_id"],
      "same body, different master_salt -> different claim_id")

# H9 (saltzer N1 / kind minimization): revocation check passes WITHOUT opening kind
noknd = disclose(mB, lB, open_kind=False)
check("H9 revocation check needs no kind", result(B, noknd, ledger, registry, 20) == "ACCEPT" and
      all("kind" not in d for d in noknd), "kind stays hidden; only from_claim_id is revealed")

# ====================== REPORT ======================
print("PHASE-7 EXECUTABLE PROOF — issuer-committed reliance\n" + "=" * 52)
npass = 0
for name, cond, detail in tests:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))
    npass += bool(cond)
print("=" * 52)
print(f"{npass}/{len(tests)} hypotheses hold." +
      ("  ALL PASS — design executes as specified." if npass == len(tests) else "  ⚠ FAILURES ABOVE."))
