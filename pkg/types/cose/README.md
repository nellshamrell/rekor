**COSE Type Data Documentation**

This document provides a definition for each field that is not
otherwise described in the [cose
schema](https://github.com/sigstore/rekor/blob/main/pkg/types/cose/v0.0.1/cose_v0_0_1_schema.json). This
document also notes any additional information about the values
associated with each field such as the format in which the data is
stored and any necessary transformations.

**AAD** Additional Authenticated Data.

If the COSE envelope is signed using AAD, the same data must be
provided during upload, otherwise the signature verification will
fail. This data is not stored in Rekor.

**How do you identify an object as an cose object?**

The "Body" field will include an "coseObj" field.

**Recognized content types**

- [in-toto
  statements](https://github.com/in-toto/attestation/tree/main/spec#statement)
  are recognized and parsed. The found subject hashes are indexed so
  they can be searched for.

**What data about the envelope is stored in Rekor**

Only the hash of the payload, the hash of the COSE envelope and the
public key is stored.

If Rekor is configured to use attestation storage, the entire
envelope is also stored. If attestation storage is enabled, the COSE
envelope is stored as an attestation, which means that during
retrieval of the record, the complete envelope is returned in the
`attestation` field, not within the `body`.

**Versions**

- **v0.0.1** — the original type. When attestation storage is enabled the
  server persists the entire COSE envelope as an attestation (see above).

- **v0.0.2** — a hash-only variant. The COSE Sign1 envelope is verified at
  ingest and then discarded: it is **never** persisted, regardless of the
  `enable_attestation_storage` setting. Only the public key, payload hash and
  envelope hash are stored in the log. This keeps the transparency log from
  being used as a data store and aligns the type with Rekor v2. A client that
  holds the original envelope can still prove inclusion by re-hashing it.

  v0.0.2 also broadens support for SCITT
  ([Signed Statements](https://scitt.io) are `COSE_Sign1` envelopes):

  - **Signature algorithms:** ES256 (P-256), ES384 (P-384), ES512 (P-521),
    EdDSA (Ed25519), and PS256 (RSA) are accepted and verified at ingest.
  - **`CWT_Claims` indexing:** if the protected header carries a `CWT_Claims`
    block ([RFC 9597](https://www.rfc-editor.org/rfc/rfc9597.html), label 15),
    the issuer (`iss`, claim 1) and subject (`sub`, claim 2) are emitted as the
    index keys `cwt:iss:<value>` and `cwt:sub:<value>`, so the log is queryable
    by SCITT identity through the index-search API.
  - **COSE Hash Envelope
    ([RFC 9995](https://www.rfc-editor.org/rfc/rfc9995.html)):** if the protected
    header declares `payload-hash-alg` (label 258), the payload is treated as a
    preimage digest and indexed under its declared algorithm
    (e.g. `sha256:<digest>`), so entries are searchable by the underlying
    artifact digest. Using a hash envelope is the recommended client convention
    for SCITT statements so that the artifact content is never sent to the log.

  Because v0.0.2 does not persist the envelope, the `iss`/`sub`/in-toto subject
  index keys cannot be rebuilt by `backfill-index` from a stored entry (the
  claims are gone) — the same property the `dsse` type already has.
