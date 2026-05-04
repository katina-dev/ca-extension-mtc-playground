# MTC Cert Wire-Size Experiment

**Status**: design + tooling notes for the wire-size measurement work. Saved
2026-05-04. Companion to `docs/design/wolfssl-cgo-shim.md`.

## Goal

Quantify how much data crosses the wire when a relying party verifies a
**signatureless** MTC certificate, as a function of the cert's subject-key
algorithm. Specifically: measure the per-session expansion factor when the
subject key is post-quantum (ML-DSA-44/65/87) versus classical (Ed25519,
ECDSA-P256, RSA-2048).

The downstream consumer is a wolfSSL-based simulation that sends the cert
client→server and verifies it on receipt. The data point we want is the
cert-only payload size, which is the wire payload in the steady-state model.

## Trust-anchor assumption (important)

This experiment assumes the relying party **already has the trusted subtree
information** (cosigner public key + a cosigned `(tree_size, root_hash)`
pair) before any session begins. That assumption changes what's worth
measuring:

- The cosigned checkpoint does **not** travel per-session — it's pre-shared
  out of band (pinning, registry, distribution channel of the deployer's
  choice). So checkpoint bytes are bootstrap cost, not session cost.
- The cosigner algorithm therefore does **not** affect per-session bytes.
  ML-DSA-65 vs Ed25519 cosigner only changes the bootstrap blob size.
- Per-session wire bytes = `cert_bytes`. Nothing else.

This matches MTC's design intent — the signature you'd otherwise carry per
session in a TLS handshake is replaced by a Merkle inclusion proof embedded
in the cert, anchored by a pre-shared trust root.

## What's measured

CSV columns produced by `bin/cert-size-report`:

| column | meaning |
|---|---|
| `timestamp` | RFC 3339 issue time |
| `subject_algo` | `ed25519`, `ecdsa256`, `rsa2048`, `mldsa44`, `mldsa65`, `mldsa87` |
| `leaf_index` | Merkle leaf index = X.509 serial in MTC mode |
| `cert_bytes` | full cert DER size (the wire payload) |
| `spki_bytes` | size of `SubjectPublicKeyInfo` octets within the cert |
| `proof_bytes` | inclusion-proof contribution (`hashes × 32`) |
| `proof_hashes` | inclusion-proof length (≈ ⌈log₂(tree_size)⌉) |
| `subtree_end` | tree size at issuance time (proof's upper bound) |

The two interesting derived quantities are:

- **Per-algo overhead** (`cert_bytes` for ML-DSA-X minus `cert_bytes` for
  Ed25519 baseline at the same `subtree_end`).
- **Proof-length growth** with tree size (plot `proof_hashes` vs
  `subtree_end` — should look logarithmic).

## What's NOT measured (and why)

- **Cosigner signature bytes**: out of scope per the trust-anchor assumption
  above. If you later decide to measure "no pre-shared anchor" cold-start
  costs, also fetch `/checkpoint` and add its size to each row.
- **TLS handshake overhead**: the wolfSSL simulation is expected to either
  tunnel cert bytes inside an already-established TLS connection or use a
  raw TCP transport; either way, comparing TLS framing across runs is the
  wolfSSL side's responsibility.
- **CA chain bytes**: the bridge serves `leaf || ca_cert` on `/cert`, but
  the report tool extracts only the leaf. In MTC mode the CA cert is
  decorative (no signature on the leaf), so it's noise for this experiment.

## Cold vs warm distinction

If you later change the assumption ("relying party has NO pre-shared trust"):

- **Cold session** (per-session checkpoint fetch): add `checkpoint_bytes` to
  each session's wire total.
- **Warm session** (steady state, this experiment): cert only.

For ML-DSA-65 the rough numbers are:
- Cold: `~2,500 (cert) + ~3,500 (checkpoint with ML-DSA-65 cosigner) = ~6,000 B`
- Warm: `~2,500 B`

So the cosigner choice matters a lot in cold-start measurements, but only at
bootstrap. Future-you reading this: don't be confused if cosigner algorithm
appears to "do nothing" in the per-session numbers — that's correct under
the trust-anchor-pre-shared assumption.

## How to run

```bash
# 1. Bridge running with MTC mode enabled (default in standalone-mode branch)
docker compose up -d

# 2. Build (also builds bin/cert-size-report)
make build

# 3. Issue the experiment matrix and write CSV
make cert-size-report COUNT_PER_ALGO=10 OUTPUT=sizes.csv

#    Or directly:
./bin/cert-size-report -count-per-algo 10 \
  -algorithms ed25519,ecdsa256,rsa2048,mldsa44,mldsa65,mldsa87 \
  -output sizes.csv -verbose
```

To measure proof-length growth across tree sizes, run repeatedly with
`bulk-issue` in between to grow the tree:

```bash
make cert-size-report COUNT_PER_ALGO=3 OUTPUT=sizes-100.csv
make bulk-issue COUNT=900     # tree now ~1000
make cert-size-report COUNT_PER_ALGO=3 OUTPUT=sizes-1000.csv
make bulk-issue COUNT=9000    # tree now ~10000
make cert-size-report COUNT_PER_ALGO=3 OUTPUT=sizes-10000.csv
```

## Worked example (smoke run, tree size ~110)

From a real run on 2026-05-04:

```
subject_algo  leaf  cert  spki  proof  hashes
ed25519       104   477   44    96     3
ecdsa256      105   559   91    128    4
rsa2048       106   760   294   128    4
mldsa44       107   1832  1334  160    5
mldsa65       108   2440  1974  128    4
mldsa87       109   3112  2614  160    5
```

Observations from this run:

- ML-DSA-65 cert is **5.1× the size of an Ed25519 cert** (2440 / 477).
- The SPKI accounts for **81%** of the ML-DSA-65 cert (1974 / 2440); the
  remaining ~466 bytes is X.509 framing + DN + extensions + MTC proof.
- Proof bytes track tree size, not algorithm. ECDSA-256 happened to land in
  a 16-leaf-aligned subtree → 4 hashes; ML-DSA-44 landed in an 8-leaf
  subtree where it needed 5 hashes. Both are independent of algorithm.

## Limitations of the current measurement

1. **Same bridge instance issues all certs**, so all samples share the same
   issuer DN and extension overhead. Different deployments with different
   trust-anchor identifiers will have slightly different envelope bytes.
2. **Tree size is monotonically increasing during the run** — later
   algorithms get slightly larger proofs. To isolate algorithm-only effect,
   compare cells at the same `subtree_end` value (or run each algorithm in
   its own bridge instance).
3. **CIRCL ML-DSA implementation is what we measure** — slight encoding
   differences vs OpenSSL 3.5's ML-DSA serializer would show as 1–2 byte
   deltas. Probably noise but worth noting if you cross-validate.
4. **No CSR signature verification on the bridge** — the permissive parser
   accepts any signature. Not a measurement issue but worth noting if your
   wolfSSL side expects the cert to be cryptographically bound to the key.

## Connection to the wolfSSL simulation

The wolfSSL client/server program:

1. Pulls one cert per algorithm from this measurement (or freshly issued
   via the bridge).
2. Sends cert bytes over its wire protocol (length-prefixed binary or
   TLS-tunneled, see `docs/design/wolfssl-cgo-shim.md`).
3. Server verifies via `mtc-verify-cert` subprocess, exit code 0 = accept.
4. Server logs bytes received per session.

Per-session wire payload should equal `cert_bytes` from the CSV plus any
protocol framing (length prefix, message type byte) the wolfSSL side adds.

For a proper PQ vs classical comparison, run sessions:
- Session A: client presents an Ed25519-key cert (baseline)
- Session B: client presents an ML-DSA-65-key cert (PQ)
- Compare `bytes_received_A` vs `bytes_received_B`. The delta should match
  `cert_bytes` delta from the CSV (within ± framing overhead).

## Files

- `cmd/cert-size-report/main.go` — measurement tool (~500 LOC)
- `internal/acme/csrparse.go` — permissive CSR parser; tolerates ML-DSA
  SPKI OIDs that pre-existing stdlib versions might reject
- `internal/acme/csrparse_test.go` — three tests covering stdlib path,
  unknown-OID path (modern stdlib accepts), and forced manual-parser path
- `Makefile` target `cert-size-report` — convenience wrapper

## Future extensions

- **Cold-start variant**: extend the tool to also fetch `/checkpoint` and
  emit `checkpoint_bytes` per row. Useful for the "no pre-shared trust"
  measurement scenario.
- **Tree-size sweeps in one run**: have the tool itself trigger
  `bulk-issue`-style tree growth between algorithm batches, so a single
  invocation produces a full grid.
- **Compression analysis**: gzip cert_bytes and report compressed size.
  ML-DSA SPKIs are high-entropy random bytes so compression does almost
  nothing — but worth confirming numerically.
