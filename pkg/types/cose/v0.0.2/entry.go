//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cose implements the "cose" transparency-log entry type at version
// 0.0.2. It differs from v0.0.1 in one important way: the COSE Sign1 envelope
// uploaded for verification is NEVER persisted by the log. The envelope is
// verified at ingest and only hashed values (public key, payload hash, envelope
// hash) plus derived index keys are stored. This mirrors the behavior of the
// dsse type and keeps the transparency log from being used as a data store,
// aligning the type with Rekor v2.
package cose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	"github.com/in-toto/in-toto-golang/in_toto"
	gocose "github.com/veraison/go-cose"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/cose"
)

const (
	APIVERSION = "0.0.2"
)

const (
	CurveP256 = "P-256"
	CurveP384 = "P-384"
	CurveP521 = "P-521"
)

// COSE Hash Envelope protected-header label (RFC 9995): payload-hash-alg is
// mandatory and identifies the hash algorithm of the digest carried as the
// payload.
const hashEnvelopePayloadHashAlg int64 = 258

// coseHashAlgToName maps COSE Hash Algorithm registry values (used by RFC 9995
// label 258) to the digest-algorithm names Rekor indexes under. Only the
// commonly used SHA-2 algorithms are mapped; unknown algorithms are ignored.
var coseHashAlgToName = map[int64]string{
	-16: "sha256",
	-43: "sha384",
	-44: "sha512",
}

// maxIndexKeyLength bounds the length of an index key, measured in characters
// (runes). The index storage layers cap key length (MySQL uses VARCHAR(512),
// which counts characters), so oversized keys are skipped rather than risking a
// failed or truncated index write.
const maxIndexKeyLength = 512

func init() {
	if err := cose.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

// V002Entry is a hash-only cose entry. The COSE Sign1 envelope
// (CoseObj.Message) is verified during Unmarshal and then cleared from memory;
// only hashes and pre-extracted index keys are retained.
type V002Entry struct {
	CoseObj      models.CoseV002Schema
	keyObj       pki.PublicKey
	sign1Msg     *gocose.Sign1Message
	envelopeHash []byte
	payloadHash  []byte
	indexKeys    []string
	isInsertable bool
}

func (v V002Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V002Entry{}
}

// IndexKeys returns the index keys extracted from the envelope during
// Unmarshal. Because the envelope is not retained, the keys are computed once at
// ingest and stored on the entry; this method simply returns them.
func (v V002Entry) IndexKeys() ([]string, error) {
	// If keys were pre-extracted at ingest (message was present), return them.
	if len(v.indexKeys) > 0 {
		return v.indexKeys, nil
	}

	// Otherwise (e.g. canonical entry retrieved from the log, where no envelope
	// is available) we can only recover the key- and hash-based index keys from
	// the stored canonical fields.
	return v.canonicalIndexKeys()
}

// canonicalIndexKeys computes the subset of index keys that can be derived from
// the canonical (hash-only) representation: the public key hash, key subjects,
// the envelope hash and the payload hash. The CWT/in-toto keys cannot be
// recovered here because the envelope is not persisted.
func (v V002Entry) canonicalIndexKeys() ([]string, error) {
	var result []string

	if v.CoseObj.PublicKey == nil {
		return nil, errors.New("missing public key")
	}
	keyObj, err := x509.NewPublicKey(bytes.NewReader(*v.CoseObj.PublicKey))
	if err != nil {
		return nil, err
	}

	key, err := keyObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		keyHash := sha256.Sum256(key)
		result = append(result, strings.ToLower(hex.EncodeToString(keyHash[:])))
	}
	result = append(result, keyObj.Subjects()...)

	if v.CoseObj.Data != nil {
		if eh := v.CoseObj.Data.EnvelopeHash; eh != nil && eh.Algorithm != nil && eh.Value != nil {
			result = append(result, strings.ToLower(fmt.Sprintf("%s:%s", *eh.Algorithm, *eh.Value)))
		}
		if ph := v.CoseObj.Data.PayloadHash; ph != nil && ph.Algorithm != nil && ph.Value != nil {
			result = append(result, strings.ToLower(fmt.Sprintf("%s:%s", *ph.Algorithm, *ph.Value)))
		}
	}

	return result, nil
}

// extractIndexKeys computes all index keys from the verified envelope at ingest
// time. It must be called after validate() has populated v.sign1Msg and after
// the payload/envelope hashes have been computed.
func (v *V002Entry) extractIndexKeys() error {
	var result []string

	if v.CoseObj.PublicKey == nil {
		return errors.New("missing public key")
	}
	keyObj, err := x509.NewPublicKey(bytes.NewReader(*v.CoseObj.PublicKey))
	if err != nil {
		return err
	}

	// 1. Key
	key, err := keyObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		keyHash := sha256.Sum256(key)
		result = append(result, strings.ToLower(hex.EncodeToString(keyHash[:])))
	}
	result = append(result, keyObj.Subjects()...)

	// 2. Overall envelope (use the pre-computed hash; the envelope itself is not
	// retained beyond ingest).
	result = append(result, hashIndexKey(v.envelopeHash))

	// 3. Payload
	if v.sign1Msg == nil {
		v.indexKeys = result
		return nil
	}
	result = append(result, hashIndexKey(v.payloadHash))

	// If payload is an in-toto statement, grab the subjects.
	if rawContentType, ok := v.sign1Msg.Headers.Protected[gocose.HeaderLabelContentType]; ok {
		contentType, ok := rawContentType.(string)
		// Integers as defined by CoAP content format are valid too,
		// but in-toto payload type is not defined there, so only
		// proceed if content type is a string.
		if ok && contentType == in_toto.PayloadType {
			stmt, err := getIntotoStatement(v.sign1Msg.Payload)
			if err != nil {
				log.Logger.Warnf("Failed to parse intoto statement")
			} else {
				for _, sub := range stmt.Subject {
					for alg, digest := range sub.Digest {
						result = append(result, alg+":"+digest)
					}
				}
			}
		}
	}

	// If the protected header carries SCITT/CWT_Claims (label 15), index the
	// issuer (iss=1) and subject (sub=2) so the log is queryable by SCITT
	// identity. Missing or malformed claims are ignored (best-effort indexing).
	if rawClaims, ok := v.sign1Msg.Headers.Protected[gocose.HeaderLabelCWTClaims]; ok {
		if claims, ok := rawClaims.(map[any]any); ok {
			if key, ok := cwtIndexKey(claims, gocose.CWTClaimIssuer, "cwt:iss:"); ok {
				result = append(result, key)
			}
			if key, ok := cwtIndexKey(claims, gocose.CWTClaimSubject, "cwt:sub:"); ok {
				result = append(result, key)
			}
		}
	}

	// If this is a COSE Hash Envelope (RFC 9995), the payload is the digest of
	// the preimage content. Index that preimage digest under its declared
	// algorithm (label 258) so the log is searchable by the artifact digest,
	// not just by sha256 of the digest-payload. Best-effort: unknown or
	// malformed hash algorithms are ignored.
	if key, ok := hashEnvelopeIndexKey(v.sign1Msg); ok {
		result = append(result, key)
	}

	v.indexKeys = result
	return nil
}

// hashEnvelopeIndexKey returns an index key for the preimage digest of a COSE
// Hash Envelope (RFC 9995), formatted as "<alg>:<hexdigest>". It returns false
// if the envelope is not a hash envelope, the algorithm is unknown, or the
// digest length does not match the declared algorithm.
func hashEnvelopeIndexKey(msg *gocose.Sign1Message) (string, bool) {
	rawAlg, ok := msg.Headers.Protected[hashEnvelopePayloadHashAlg]
	if !ok {
		return "", false
	}
	algVal, ok := toInt64(rawAlg)
	if !ok {
		return "", false
	}
	algName, ok := coseHashAlgToName[algVal]
	if !ok {
		return "", false
	}
	if len(msg.Payload) == 0 {
		return "", false
	}
	// Sanity-check the digest length against the declared algorithm.
	expectedLen := map[string]int{"sha256": 32, "sha384": 48, "sha512": 64}[algName]
	if len(msg.Payload) != expectedLen {
		return "", false
	}
	key := algName + ":" + strings.ToLower(hex.EncodeToString(msg.Payload))
	if utf8.RuneCountInString(key) > maxIndexKeyLength {
		return "", false
	}
	return key, true
}

// toInt64 normalizes the CBOR-decoded integer types that a COSE header value
// may present as.
func toInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case int:
		return int64(t), true
	case int32:
		return int64(t), true
	case gocose.Algorithm:
		return int64(t), true
	default:
		return 0, false
	}
}

// cwtIndexKey returns the namespaced index key for a CWT claim if the claim is
// present, a non-empty string, and the resulting key fits within the index key
// length bound. The claim value is lowercased so lookups (which lowercase the
// query) match regardless of database collation, consistent with how other
// Rekor index keys are canonicalized. CBOR integer labels decode as int64.
func cwtIndexKey(claims map[any]any, label int64, prefix string) (string, bool) {
	raw, ok := claims[label]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", false
	}
	key := prefix + strings.ToLower(s)
	if utf8.RuneCountInString(key) > maxIndexKeyLength {
		return "", false
	}
	return key, true
}

func getIntotoStatement(b []byte) (*in_toto.Statement, error) {
	var stmt in_toto.Statement
	if err := json.Unmarshal(b, &stmt); err != nil {
		return nil, err
	}

	return &stmt, nil
}

// hashIndexKey formats a pre-computed sha256 digest as a namespaced index key.
func hashIndexKey(digest []byte) string {
	return strings.ToLower(fmt.Sprintf("%s:%s", models.CoseV002SchemaDataPayloadHashAlgorithmSha256, hex.EncodeToString(digest)))
}

func (v *V002Entry) Unmarshal(pe models.ProposedEntry) error {
	it, ok := pe.(*models.Cose)
	if !ok {
		return errors.New("cannot unmarshal non Cose v0.0.2 type")
	}

	var err error
	if err := DecodeEntry(it.Spec, &v.CoseObj); err != nil {
		return err
	}

	// field validation
	if err := v.CoseObj.Validate(strfmt.Default); err != nil {
		return err
	}

	if v.CoseObj.PublicKey == nil {
		return errors.New("missing public key")
	}
	v.keyObj, err = x509.NewPublicKey(bytes.NewReader(*v.CoseObj.PublicKey))
	if err != nil {
		return err
	}

	// The CoseObj.Message is only populated during entry creation (upload).
	// When unmarshalling a canonical entry retrieved from the log there is no
	// envelope, so the hashes must be recovered from the stored hex strings.
	if len(v.CoseObj.Message) == 0 {
		if v.CoseObj.Data == nil || v.CoseObj.Data.EnvelopeHash == nil || v.CoseObj.Data.EnvelopeHash.Value == nil {
			return errors.New("envelope hash should have been previously computed")
		}
		if v.CoseObj.Data.PayloadHash == nil || v.CoseObj.Data.PayloadHash.Value == nil {
			return errors.New("payload hash should have been previously computed")
		}
		eh, err := hex.DecodeString(*v.CoseObj.Data.EnvelopeHash.Value)
		if err != nil {
			return err
		}
		ph, err := hex.DecodeString(*v.CoseObj.Data.PayloadHash.Value)
		if err != nil {
			return err
		}
		v.envelopeHash = eh
		v.payloadHash = ph
		return nil
	}

	h := sha256.Sum256(v.CoseObj.Message)
	v.envelopeHash = h[:]

	// Verify the COSE signature over the envelope. This must succeed before we
	// discard the envelope.
	if err := v.validate(); err != nil {
		return err
	}

	// Compute the payload hash and extract all index keys while the verified
	// envelope/payload are still available.
	if v.sign1Msg == nil || v.sign1Msg.Payload == nil {
		return errors.New("payload empty")
	}
	ph := sha256.Sum256(v.sign1Msg.Payload)
	v.payloadHash = ph[:]

	if err := v.extractIndexKeys(); err != nil {
		return err
	}

	v.isInsertable = true

	// Hash-only storage: drop the envelope and payload from memory now that the
	// signature is verified and all hashes/index keys are extracted. The
	// envelope is never persisted.
	v.CoseObj.Message = nil
	v.sign1Msg.Payload = nil

	return nil
}

func (v *V002Entry) Canonicalize(_ context.Context) ([]byte, error) {
	if v.keyObj == nil {
		return nil, errors.New("cannot canonicalize empty key")
	}
	if len(v.payloadHash) == 0 {
		return nil, errors.New("payload hash has not been computed")
	}
	if len(v.envelopeHash) == 0 {
		return nil, errors.New("envelope hash has not been computed")
	}

	pk, err := v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	pkb := strfmt.Base64(pk)

	canonicalEntry := models.CoseV002Schema{
		PublicKey: &pkb,
		Data: &models.CoseV002SchemaData{
			PayloadHash: &models.CoseV002SchemaDataPayloadHash{
				Algorithm: conv.Pointer(models.CoseV002SchemaDataPayloadHashAlgorithmSha256),
				Value:     conv.Pointer(hex.EncodeToString(v.payloadHash)),
			},
			EnvelopeHash: &models.CoseV002SchemaDataEnvelopeHash{
				Algorithm: conv.Pointer(models.CoseV002SchemaDataEnvelopeHashAlgorithmSha256),
				Value:     conv.Pointer(hex.EncodeToString(v.envelopeHash)),
			},
		},
	}

	itObj := models.Cose{}
	itObj.APIVersion = conv.Pointer(APIVERSION)
	itObj.Spec = &canonicalEntry

	return json.Marshal(&itObj)
}

// validate performs cross-field validation for fields in object
func (v *V002Entry) validate() error {
	// This also gets called in the CLI, where we won't have this data
	// or during record retrieval (there is no envelope for hash-only entries).
	if len(v.CoseObj.Message) == 0 {
		return nil
	}

	alg, pk, err := getPublicKey(v.keyObj)
	if err != nil {
		return err
	}

	bv, err := gocose.NewVerifier(alg, pk)
	if err != nil {
		return err
	}
	sign1Msg := gocose.NewSign1Message()
	if err := sign1Msg.UnmarshalCBOR(v.CoseObj.Message); err != nil {
		return err
	}

	// AAD is optional; guard against a nil Data property so a proposed entry
	// without a data block does not panic.
	var aad []byte
	if v.CoseObj.Data != nil {
		aad = v.CoseObj.Data.Aad
	}
	if err := sign1Msg.Verify(aad, bv); err != nil {
		return err
	}

	v.sign1Msg = sign1Msg
	return nil
}

func getPublicKey(pk pki.PublicKey) (gocose.Algorithm, crypto.PublicKey, error) {
	invAlg := gocose.Algorithm(0)
	x5pk, ok := pk.(*x509.PublicKey)

	if !ok {
		return invAlg, nil, errors.New("invalid public key type")
	}

	cryptoPub := x5pk.CryptoPubKey()

	var alg gocose.Algorithm
	switch t := cryptoPub.(type) {
	case *rsa.PublicKey:
		// The COSE RSASSA-PSS algorithm cannot be disambiguated from the key
		// alone; default to PS256. The protected-header alg is still enforced
		// by go-cose during verification.
		alg = gocose.AlgorithmPS256
	case *ecdsa.PublicKey:
		// The elliptic curve determines the ECDSA COSE algorithm.
		switch t.Params().Name {
		case CurveP256:
			alg = gocose.AlgorithmES256
		case CurveP384:
			alg = gocose.AlgorithmES384
		case CurveP521:
			alg = gocose.AlgorithmES512
		default:
			return invAlg, nil, fmt.Errorf("unsupported elliptic curve %s",
				t.Params().Name)
		}
	case ed25519.PublicKey:
		alg = gocose.AlgorithmEdDSA
	default:
		return invAlg, nil, fmt.Errorf("unsupported algorithm type %T", t)
	}

	return alg, cryptoPub, nil
}

// DecodeEntry performs direct decode into the provided output pointer
// without mutating the receiver on error.
func DecodeEntry(input any, output *models.CoseV002Schema) error {
	if output == nil {
		return fmt.Errorf("nil output *models.CoseV002Schema")
	}
	var m models.CoseV002Schema
	// Typed switch including map fast path
	switch data := input.(type) {
	case map[string]any:
		mm := data
		if msg, ok := mm["message"].(string); ok && msg != "" {
			outb := make([]byte, base64.StdEncoding.DecodedLen(len(msg)))
			n, err := base64.StdEncoding.Decode(outb, []byte(msg))
			if err != nil {
				return fmt.Errorf("failed parsing base64 data for message: %w", err)
			}
			m.Message = strfmt.Base64(outb[:n])
		}
		if pk, ok := mm["publicKey"].(string); ok && pk != "" {
			outb := make([]byte, base64.StdEncoding.DecodedLen(len(pk)))
			n, err := base64.StdEncoding.Decode(outb, []byte(pk))
			if err != nil {
				return fmt.Errorf("failed parsing base64 data for publicKey: %w", err)
			}
			b := strfmt.Base64(outb[:n])
			m.PublicKey = &b
		}
		if d, ok := mm["data"].(map[string]any); ok {
			m.Data = &models.CoseV002SchemaData{}
			if ph, ok := d["payloadHash"].(map[string]any); ok {
				m.Data.PayloadHash = &models.CoseV002SchemaDataPayloadHash{}
				if alg, ok := ph["algorithm"].(string); ok {
					m.Data.PayloadHash.Algorithm = &alg
				}
				if val, ok := ph["value"].(string); ok {
					m.Data.PayloadHash.Value = &val
				}
			}
			if eh, ok := d["envelopeHash"].(map[string]any); ok {
				m.Data.EnvelopeHash = &models.CoseV002SchemaDataEnvelopeHash{}
				if alg, ok := eh["algorithm"].(string); ok {
					m.Data.EnvelopeHash.Algorithm = &alg
				}
				if val, ok := eh["value"].(string); ok {
					m.Data.EnvelopeHash.Value = &val
				}
			}
			if aad, ok := d["aad"].(string); ok && aad != "" {
				outb := make([]byte, base64.StdEncoding.DecodedLen(len(aad)))
				n, err := base64.StdEncoding.Decode(outb, []byte(aad))
				if err != nil {
					return fmt.Errorf("failed parsing base64 data for aad: %w", err)
				}
				m.Data.Aad = strfmt.Base64(outb[:n])
			}
		}
		*output = m
		return nil
	case *models.CoseV002Schema:
		if data == nil {
			return fmt.Errorf("nil *models.CoseV002Schema")
		}
		*output = *data
		return nil
	case models.CoseV002Schema:
		*output = data
		return nil
	default:
		return fmt.Errorf("unsupported input type %T for DecodeEntry", input)
	}
}

func (v V002Entry) CreateFromArtifactProperties(_ context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	returnVal := models.Cose{}
	var err error
	messageBytes := props.ArtifactBytes
	if messageBytes == nil {
		if props.ArtifactPath == nil {
			return nil, errors.New("path to artifact file must be specified")
		}
		if props.ArtifactPath.IsAbs() {
			return nil, errors.New("cose envelopes cannot be fetched over HTTP(S)")
		}
		messageBytes, err = os.ReadFile(filepath.Clean(props.ArtifactPath.Path))
		if err != nil {
			return nil, err
		}
	}
	publicKeyBytes := props.PublicKeyBytes
	if len(publicKeyBytes) == 0 {
		if len(props.PublicKeyPaths) != 1 {
			return nil, errors.New("only one public key must be provided to verify signature")
		}
		keyBytes, err := os.ReadFile(filepath.Clean(props.PublicKeyPaths[0].Path))
		if err != nil {
			return nil, fmt.Errorf("error reading public key file: %w", err)
		}
		publicKeyBytes = append(publicKeyBytes, keyBytes)
	} else if len(publicKeyBytes) != 1 {
		return nil, errors.New("only one public key must be provided")
	}

	kb := strfmt.Base64(publicKeyBytes[0])
	mb := strfmt.Base64(messageBytes)

	re := V002Entry{
		CoseObj: models.CoseV002Schema{
			Data: &models.CoseV002SchemaData{
				Aad: props.AdditionalAuthenticatedData,
			},
			PublicKey: &kb,
			Message:   mb,
		},
	}

	returnVal.Spec = re.CoseObj
	returnVal.APIVersion = conv.Pointer(re.APIVersion())

	return &returnVal, nil
}

func (v V002Entry) Verifiers() ([]pki.PublicKey, error) {
	if v.CoseObj.PublicKey == nil {
		return nil, errors.New("cose v0.0.2 entry not initialized")
	}
	key, err := x509.NewPublicKey(bytes.NewReader(*v.CoseObj.PublicKey))
	if err != nil {
		return nil, err
	}
	return []pki.PublicKey{key}, nil
}

func (v V002Entry) ArtifactHash() (string, error) {
	if v.CoseObj.Data == nil || v.CoseObj.Data.PayloadHash == nil || v.CoseObj.Data.PayloadHash.Value == nil || v.CoseObj.Data.PayloadHash.Algorithm == nil {
		return "", errors.New("cose v0.0.2 entry not initialized")
	}
	return strings.ToLower(fmt.Sprintf("%s:%s", *v.CoseObj.Data.PayloadHash.Algorithm, *v.CoseObj.Data.PayloadHash.Value)), nil
}

func (v V002Entry) Insertable() (bool, error) {
	if !v.isInsertable {
		return false, errors.New("entry has not been validated for insertion")
	}
	if v.CoseObj.PublicKey == nil || len(*v.CoseObj.PublicKey) == 0 {
		return false, errors.New("missing public key")
	}
	if len(v.envelopeHash) == 0 {
		return false, errors.New("envelope hash has not been computed")
	}
	if len(v.payloadHash) == 0 {
		return false, errors.New("payload hash has not been computed")
	}
	if v.keyObj == nil {
		return false, errors.New("public key has not been parsed")
	}
	if v.sign1Msg == nil {
		return false, errors.New("signature has not been validated")
	}

	return true, nil
}
