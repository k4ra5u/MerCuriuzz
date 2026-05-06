# QUIC Hunter Identification Logic In `quic_pipeline_tui`

## Phase Layout

- `phase1`: parse ZMap UDP replies and classify them as `quic-vn`, `quic-lh`, or `invalid`
- `phase2`: query PDNS and write domain candidates
- `phase3`: only validate PDNS results with a normal `ALPN=h3` handshake and write `connect.jsonl`
- `phase4`: run the 8-stage measurement pipeline
- `phase5`: optional QUIC Hunter implementation identification, disabled by default, writing `identify.jsonl`

Enable phase5 explicitly:

```bash
cargo run -p quic_pipeline_tui -- /path/to/zmap.csv \
  --run-phase1 false \
  --run-phase2 false \
  --run-phase3 false \
  --run-phase4 false \
  --run-phase5 true
```

## Phase5 Inputs And Skip Rules

Phase5 merges metadata from earlier outputs with the following priority:

1. `connect.jsonl`
   This is the primary prerequisite. It decides whether a target is actively reprobed.
2. `pdns.jsonl`
   Supplies `row`, `versions`, `quic_libs`, `phase1_class`, and PDNS-derived context.
3. `versions.csv`
   Used as fallback when `pdns.jsonl` is missing phase1 fields.
4. `measure.jsonl`
   Only used to supplement `selected_domain`, `source_status`, and `source_note` when connect metadata is incomplete.

Skip behavior:

- If `identify.jsonl` already has a row for an IP, phase5 skips it.
- If `connect.jsonl` says `status=connected`, phase5 performs active QUIC Hunter reprobes.
- If `connect.jsonl` is present but the IP is not connected, phase5 does not redo PDNS validation and emits only weak identification based on phase1 version fingerprints or `unknown`.

## Why Old `connect.jsonl` Is Not Enough

The old connect phase only records:

- whether the target was reachable with a normal `h3` handshake
- the selected SNI / domain
- the coarse failure note

QUIC Hunter identification additionally needs:

- one `ALPN=invalid` handshake to observe the peer close reason
- one successful `ALPN=h3` handshake with CRYPTO-frame capture to extract:
  - `ServerHello` extension order
  - QUIC transport parameter order
- two extra `ALPN=h3` replays for permutation families

Those signals are not stored in old `connect.jsonl`, so they cannot be reconstructed fully offline.

## Canonical Naming

`fuzzers/quic_pipeline_tui/src/quic_hunter.rs` is the single local registry for implementation naming and fingerprints.

Normalization rules include:

- `QUICHE` and `quiche` -> `cf-quiche`
- `AKAMAI#1` and `AKAMAI#2` -> `akamai`
- `haskellquic` -> `haskell-quic`
- labels with `#1` / `#2` keep only the base implementation family

Phase1 version labels are normalized through the same registry before participating in voting.

## ALPN Error Fingerprints

Phase5 sends one handshake with `ALPN=["invalid"]` and classifies the peer close reason using the QUIC Hunter table derived from `vendors/libraries/identification/classify_alpn.py`.

Mapped families:

- `cf-quiche`
- `akamai`
- `lsquic`
- `quant`
- `kwik`
- `aioquic`
- `nginx`
- `quinn`
- `mvfst`

The raw peer close reason is kept in `identify.jsonl.peer_close.reason`.

## TLS / Transport-Parameter Fingerprints

Phase5 sends one normal `ALPN=["h3"]` handshake and rebuilds the server TLS byte stream from observed handshake CRYPTO frames.

Extraction rules:

- `ServerHello` extension order keeps only extension ids `51` and `43`
- `EncryptedExtensions` is scanned for QUIC transport parameters in extension `57` or `65445`
- QUIC transport parameters are parsed as varints and only the parameter type order is retained

The final raw key is:

```text
ServerHelloExtensionOrder_TransportParameterOrder
```

Example:

```text
51-43_0x4-0x6-0x7-0x8-0x0-0xf
```

Exact fingerprint families currently replicated from `vendors/libraries/identification/classify_tlstp.py` include:

- `s2n-quic`
- `lsquic`
- `ngtcp2`
- `xquic`
- `haskell-quic`
- `haproxy`
- `quinn`
- `quic-go`
- `picoquic`
- `quicly`
- `mvfst`
- `cf-quiche`
- `aioquic`
- `nginx`
- `msquic`

## Permutation Families And Extra Replays

Some QUIC Hunter families are identified by parameter-set permutation rather than one exact order. These are replicated locally from `classify_tlstp.py`:

- `google-quiche`
- `akamai`
- `quant`
- `neqo`

When the first `h3` observation hits a permutation family:

1. phase5 runs 2 additional `ALPN=h3` handshakes
2. if at least 2 distinct raw TP fingerprints are observed across the 3 runs, the target is labeled as the permutation family
3. if all 3 runs stay on one exact fingerprint and an exact implementation label is available, phase5 prefers the exact implementation
4. if replay is incomplete, phase5 keeps the current TP-derived family and records the replay note in `collision_note`

## Vote Priority And Conflict Handling

Final identification follows a fixed priority:

1. `tp_order_fp`
2. `alpn_error_fp`
3. `version_fp`

Rules:

- a unique TP result wins
- if ALPN disagrees with TP, `vote_result` still follows TP and the mismatch is recorded in `collision_note`
- if TP is missing, ALPN wins over phase1 version fingerprints
- if both TP and ALPN are missing, phase1 version matching is the fallback
- if all signals are missing, `vote_result` becomes `unknown`

`identify.jsonl` keeps the raw evidence needed for audit:

- `signals.version_fp`
- `signals.alpn_error_fp`
- `signals.tp_order_fp`
- `peer_close.reason`
- `handshake_observation.fingerprint`
- `collision_note`

