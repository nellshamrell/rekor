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

**Supported signature algorithms**

The COSE signature is verified with
[veraison/go-cose](https://github.com/veraison/go-cose). The signing
algorithm is inferred from the supplied public key:

- ECDSA `P-256` → `ES256`, `P-384` → `ES384`, `P-521` → `ES512`
- Ed25519 → `EdDSA`
- RSA → `PS256`

The algorithm advertised in the COSE protected header must match, or
verification fails.

**SCITT CWT_Claims indexing**

If the COSE protected header contains `CWT_Claims` (label `15`, see
[RFC 9597](https://datatracker.ietf.org/doc/html/rfc9597)) — as used by
[SCITT](https://scitt.io) Signed Statements — the issuer (`iss`, claim
`1`) and subject (`sub`, claim `2`) string values are indexed as
`cwt:iss:<value>` and `cwt:sub:<value>` so they can be searched for.
The claim value is lowercased before indexing, so lookups are
case-insensitive (the search API lowercases the query), consistent with
how other Rekor index keys are canonicalized. Only string claim values
are indexed, and only when the resulting namespaced index key fits
within the 512-character index key limit (matching the `VARCHAR(512)`
index column); missing or malformed CWT_Claims are ignored.

Search using the full namespaced key as the subject, for example:

```
rekor-cli search --subject "cwt:sub:pkg:oci/example-app@sha256:abcd"
rekor-cli search --subject "cwt:iss:did:web:issuer.example"
```

Note that this indexing applies to newly submitted entries only — the
canonical stored body does not retain the raw COSE envelope, so the
existing canonical-entry backfill cannot reconstruct these keys. Any CWT
index keys not captured correctly at submission time (for example,
entries logged before this feature) cannot be recovered later.

**What data about the envelope is stored in Rekor**

Only the hash of the payload, the hash of the COSE envelope and the
public key is stored.

If Rekor is configured to use attestation storage, the entire
envelope is also stored. If attestation storage is enabled, the COSE
envelope is stored as an attestation, which means that during
retrieval of the record, the complete envelope is returned in the
`attestation` field, not within the `body`.
