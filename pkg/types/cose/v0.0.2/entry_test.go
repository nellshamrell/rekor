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

package cose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/pki/identity"
	sigx509 "github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/types"
	gocose "github.com/veraison/go-cose"
	"go.uber.org/goleak"
)

const (
	pubKeyP256 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5P3tzcNDA11znnCFF3DHLwiHNCl3
OXbUFakqff3cSRd4OTH1hiJgi15VIGSKZALlqjdWpf+fs87uRpiI6Yp59A==
-----END PUBLIC KEY-----
`
	pubKeyRSA2048 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuqO4gwscYmCE3P8eM9eg
yIiElLNAzjWapPn99/uFAFKqkinGr/DAejP2zxgdXk+ESd8bO0Rqob1WZL8/HqQN
8kRkf2KfR7d6jFe06V7N/Fmh+3YCcNNS6K9eW86u31sjnszgdtmWDrXhsH+M0W8g
Q7rmo+7BUJAcU39iApN2GNsji6vrRLRiEnMP/fpnsLa8qYpPToSE0YVfWrKOvY2q
Qhg/LceADsJzdYP0Yp+Q2jdC1J5OvUC4Mq08YdD7EawWJ5JI2qEkcPgPn5SqPomS
ihKHDVzm+FqHEbgx0P57ZdKnk8kALNz5FFdwq46mbY8FRqGD56r4sB5rRcxy0cbB
EQIDAQAB
-----END PUBLIC KEY-----
`
)

type testPublicKey int

func (t testPublicKey) CanonicalValue() ([]byte, error) {
	return nil, nil
}

func (t testPublicKey) EmailAddresses() []string {
	return nil
}

func (t testPublicKey) Subjects() []string {
	return nil
}

func (t testPublicKey) Identities() ([]identity.Identity, error) {
	return nil, nil
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestNewEntryReturnType(t *testing.T) {
	entry := NewEntry()
	if reflect.TypeOf(entry) != reflect.ValueOf(&V002Entry{}).Type() {
		t.Errorf("invalid type returned from NewEntry: %T", entry)
	}
}

func p(b []byte) *strfmt.Base64 {
	b64 := strfmt.Base64(b)
	return &b64
}

// pubPEMFromSigner returns the PKIX PEM-encoded public key for a signer.
func pubPEMFromSigner(t *testing.T, priv crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Bytes: der, Type: "PUBLIC KEY"})
}

// makeSignedCose builds a COSE Sign1 envelope over payload with the given
// algorithm, optional AAD, optional content type, and optional CWT claims.
func makeSignedCose(t *testing.T, priv crypto.Signer, alg gocose.Algorithm, payload, aad []byte, contentType interface{}, cwtClaims map[any]any) []byte {
	t.Helper()
	m := gocose.NewSign1Message()
	m.Payload = payload
	m.Headers.Protected[gocose.HeaderLabelAlgorithm] = alg

	if contentType != "" {
		m.Headers.Protected[gocose.HeaderLabelContentType] = contentType
	}
	if cwtClaims != nil {
		m.Headers.Protected[gocose.HeaderLabelCWTClaims] = cwtClaims
	}

	signer, err := gocose.NewSigner(alg, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sign(rand.Reader, aad, signer); err != nil {
		t.Fatal(err)
	}
	msg, err := m.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestV002Entry_Unmarshal(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := pubPEMFromSigner(t, priv)

	msg := makeSignedCose(t, priv, gocose.AlgorithmES256, []byte("hello"), nil, "", nil)
	msgWithAAD := makeSignedCose(t, priv, gocose.AlgorithmES256, []byte("hello"), []byte("external aad"), "", nil)

	tests := []struct {
		name    string
		it      *models.CoseV002Schema
		wantErr bool
	}{
		{
			name:    "empty",
			it:      &models.CoseV002Schema{},
			wantErr: true,
		},
		{
			name: "missing envelope",
			it: &models.CoseV002Schema{
				Data:      &models.CoseV002SchemaData{},
				PublicKey: p([]byte("hello")),
			},
			wantErr: true,
		},
		{
			name: "valid",
			it: &models.CoseV002Schema{
				Data:      &models.CoseV002SchemaData{},
				PublicKey: p(pub),
				Message:   msg,
			},
			wantErr: false,
		},
		{
			name: "valid with nil data (no aad)",
			it: &models.CoseV002Schema{
				PublicKey: p(pub),
				Message:   msg,
			},
			wantErr: false,
		},
		{
			name: "valid with aad",
			it: &models.CoseV002Schema{
				Data: &models.CoseV002SchemaData{
					Aad: strfmt.Base64("external aad"),
				},
				PublicKey: p(pub),
				Message:   msgWithAAD,
			},
			wantErr: false,
		},
		{
			name: "extra aad",
			it: &models.CoseV002Schema{
				Data: &models.CoseV002SchemaData{
					Aad: strfmt.Base64("aad"),
				},
				PublicKey: p(pub),
				Message:   msg,
			},
			wantErr: true,
		},
		{
			name: "invalid envelope",
			it: &models.CoseV002Schema{
				Data:      &models.CoseV002SchemaData{},
				PublicKey: p(pub),
				Message:   []byte("hello"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &V002Entry{}
			it := &models.Cose{Spec: tt.it}
			if err := v.Unmarshal(it); (err != nil) != tt.wantErr {
				t.Fatalf("V002Entry.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// Hash-only invariant: the envelope must be cleared after ingest.
			if len(v.CoseObj.Message) != 0 {
				t.Errorf("envelope was not cleared from memory after Unmarshal")
			}
			if v.sign1Msg != nil && v.sign1Msg.Payload != nil {
				t.Errorf("payload was not cleared from memory after Unmarshal")
			}

			if ok, err := v.Insertable(); !ok || err != nil {
				t.Errorf("unexpected error calling Insertable on valid proposed entry: %v", err)
			}

			// Canonicalize and confirm the canonical (retrieved) entry is
			// hash-only and no longer insertable.
			b, err := v.Canonicalize(context.Background())
			if err != nil {
				t.Fatalf("unexpected error canonicalizing: %v", err)
			}
			pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
			if err != nil {
				t.Fatalf("unexpected err unmarshalling canonicalized entry: %v", err)
			}
			ei, err := types.UnmarshalEntry(pe)
			if err != nil {
				t.Fatalf("unexpected err type-unmarshalling canonicalized entry: %v", err)
			}
			if ok, err := ei.Insertable(); ok || err == nil {
				t.Errorf("entry created from canonicalized entry should not be insertable")
			}

			// Idempotence: re-canonicalizing the rehydrated entry must succeed
			// and produce byte-identical output.
			b2, err := ei.Canonicalize(context.Background())
			if err != nil {
				t.Fatalf("unexpected error re-canonicalizing retrieved entry: %v", err)
			}
			if !bytes.Equal(b, b2) {
				t.Errorf("canonicalization is not idempotent:\n first: %s\nsecond: %s", string(b), string(b2))
			}
			hash, err := ei.ArtifactHash()
			expectedHash := sha256.Sum256([]byte("hello"))
			if err != nil {
				t.Errorf("unexpected failure with ArtifactHash: %v", err)
			} else if hash != "sha256:"+hex.EncodeToString(expectedHash[:]) {
				t.Errorf("unexpected ArtifactHash: %s", hash)
			}
		})
	}

	t.Run("invalid type", func(t *testing.T) {
		want := "cannot unmarshal non Cose v0.0.2 type"
		v := V002Entry{}
		if err := v.Unmarshal(&types.BaseProposedEntryTester{}); err == nil {
			t.Error("expected error")
		} else if err.Error() != want {
			t.Errorf("wrong error: %s", err.Error())
		}
	})
}

// TestV002Entry_NoAttestation confirms the type never persists the envelope:
// it must not implement EntryWithAttestationImpl.
func TestV002Entry_NoAttestation(t *testing.T) {
	var e types.EntryImpl = NewEntry()
	if _, ok := e.(types.EntryWithAttestationImpl); ok {
		t.Fatal("cose v0.0.2 must not implement EntryWithAttestationImpl (envelope must not be persisted)")
	}
}

func TestV002Entry_IndexKeys(t *testing.T) {
	payloadType := "application/vnd.in-toto+json"
	attestation := `
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "foo",
      "digest": {
        "sha256": "ad92c12d7947cc04000948248ccf305682f395af3e109ed044081dbb40182e6c"
      }
    }
  ],
  "predicate": {"builder": {"id": "https://example.com/test-builder"}, "buildType": "test"}
}
`
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := pubPEMFromSigner(t, priv)

	rawMsg := []byte(attestation)
	msg := makeSignedCose(t, priv, gocose.AlgorithmES256, rawMsg, nil, payloadType, nil)

	v := &V002Entry{}
	if err := v.Unmarshal(&models.Cose{Spec: &models.CoseV002Schema{
		Message:   msg,
		Data:      &models.CoseV002SchemaData{},
		PublicKey: p(pub),
	}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := v.IndexKeys()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Envelope digest
	sha := sha256.Sum256(msg)
	mustContain(t, "sha256:"+hex.EncodeToString(sha[:]), got)
	// Payload digest
	sha = sha256.Sum256(rawMsg)
	mustContain(t, "sha256:"+hex.EncodeToString(sha[:]), got)
	// Subject from in-toto statement
	mustContain(t, "sha256:ad92c12d7947cc04000948248ccf305682f395af3e109ed044081dbb40182e6c", got)
}

// TestV002Entry_CWTIndexKeys confirms SCITT CWT_Claims (iss/sub) are indexed.
func TestV002Entry_CWTIndexKeys(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := pubPEMFromSigner(t, priv)

	claims := map[any]any{
		gocose.CWTClaimIssuer:  "did:web:issuer.example",
		gocose.CWTClaimSubject: "pkg:oci/example-app@sha256:bbbb",
	}
	msg := makeSignedCose(t, priv, gocose.AlgorithmES256, []byte("statement"), nil, "", claims)

	v := &V002Entry{}
	if err := v.Unmarshal(&models.Cose{Spec: &models.CoseV002Schema{
		Message:   msg,
		Data:      &models.CoseV002SchemaData{},
		PublicKey: p(pub),
	}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := v.IndexKeys()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	mustContain(t, "cwt:iss:did:web:issuer.example", got)
	mustContain(t, "cwt:sub:pkg:oci/example-app@sha256:bbbb", got)
}

// TestV002Entry_Algorithms exercises the broadened signature algorithm support
// required for SCITT: ES256, ES384, ES512, and EdDSA.
func TestV002Entry_Algorithms(t *testing.T) {
	ecKey := func(c elliptic.Curve) crypto.Signer {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		priv crypto.Signer
		alg  gocose.Algorithm
	}{
		{"ES256", ecKey(elliptic.P256()), gocose.AlgorithmES256},
		{"ES384", ecKey(elliptic.P384()), gocose.AlgorithmES384},
		{"ES512", ecKey(elliptic.P521()), gocose.AlgorithmES512},
		{"EdDSA", edPriv, gocose.AlgorithmEdDSA},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub := pubPEMFromSigner(t, tc.priv)
			msg := makeSignedCose(t, tc.priv, tc.alg, []byte("hello"), nil, "", nil)
			v := &V002Entry{}
			if err := v.Unmarshal(&models.Cose{Spec: &models.CoseV002Schema{
				Message:   msg,
				Data:      &models.CoseV002SchemaData{},
				PublicKey: p(pub),
			}}); err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
			if ok, err := v.Insertable(); !ok || err != nil {
				t.Errorf("%s: unexpected Insertable error: %v", tc.name, err)
			}
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	cases := []struct {
		name    string
		pem     string
		wantAlg gocose.Algorithm
		wantErr bool
	}{
		{"P256", pubKeyP256, gocose.AlgorithmES256, false},
		{"RSA2048", pubKeyRSA2048, gocose.AlgorithmPS256, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pk, err := sigx509.NewPublicKey(bytes.NewBufferString(tc.pem))
			if err != nil {
				t.Fatal("failed to load public key")
			}
			alg, cpk, err := getPublicKey(pk)
			if (err != nil) != tc.wantErr {
				t.Errorf("unexpected err = %v", err)
			}
			if !tc.wantErr {
				if alg != tc.wantAlg {
					t.Errorf("wrong algorithm: got %v want %v", alg, tc.wantAlg)
				}
				if cpk == nil {
					t.Error("no public key returned")
				}
			}
		})
	}

	// Generated keys for ES384/ES512/EdDSA (now supported).
	genCases := []struct {
		name    string
		signer  crypto.Signer
		wantAlg gocose.Algorithm
	}{}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	genCases = append(genCases,
		struct {
			name    string
			signer  crypto.Signer
			wantAlg gocose.Algorithm
		}{"P384", p384, gocose.AlgorithmES384},
		struct {
			name    string
			signer  crypto.Signer
			wantAlg gocose.Algorithm
		}{"P521", p521, gocose.AlgorithmES512},
	)
	for _, tc := range genCases {
		t.Run(tc.name, func(t *testing.T) {
			pubPEM := pubPEMFromSigner(t, tc.signer)
			pk, err := sigx509.NewPublicKey(bytes.NewReader(pubPEM))
			if err != nil {
				t.Fatal(err)
			}
			alg, _, err := getPublicKey(pk)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if alg != tc.wantAlg {
				t.Errorf("wrong algorithm: got %v want %v", alg, tc.wantAlg)
			}
		})
	}

	t.Run("EdDSA", func(t *testing.T) {
		pubDER, err := x509.MarshalPKIXPublicKey(edPub)
		if err != nil {
			t.Fatal(err)
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
		pk, err := sigx509.NewPublicKey(bytes.NewReader(pubPEM))
		if err != nil {
			t.Fatal(err)
		}
		alg, _, err := getPublicKey(pk)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if alg != gocose.AlgorithmEdDSA {
			t.Errorf("wrong algorithm: got %v want EdDSA", alg)
		}
	})

	t.Run("Invalid key", func(t *testing.T) {
		_, _, err := getPublicKey(testPublicKey(0))
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestV002Entry_Validate(t *testing.T) {
	t.Run("missing message", func(t *testing.T) {
		v := V002Entry{}
		if err := v.validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil data does not panic", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		msg := makeSignedCose(t, priv, gocose.AlgorithmES256, []byte("hello"), nil, "", nil)
		v := V002Entry{}
		v.CoseObj.Message = msg
		v.keyObj, _ = sigx509.NewPublicKey(bytes.NewReader(pubPEMFromSigner(t, priv)))
		if err := v.validate(); err != nil {
			t.Errorf("unexpected error with nil data: %v", err)
		}
	})
}

// TestV002Entry_HashEnvelopeIndexKeys confirms a COSE Hash Envelope (RFC 9995)
// preimage digest is indexed under its declared algorithm.
func TestV002Entry_HashEnvelopeIndexKeys(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := pubPEMFromSigner(t, priv)

	// The payload of a hash envelope is the digest of the preimage content.
	preimage := []byte("the real artifact bytes")
	digest := sha256.Sum256(preimage)

	m := gocose.NewSign1Message()
	m.Payload = digest[:]
	m.Headers.Protected[gocose.HeaderLabelAlgorithm] = gocose.AlgorithmES256
	m.Headers.Protected[int64(258)] = int64(-16) // payload-hash-alg = SHA-256
	signer, err := gocose.NewSigner(gocose.AlgorithmES256, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatal(err)
	}
	msg, err := m.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	v := &V002Entry{}
	if err := v.Unmarshal(&models.Cose{Spec: &models.CoseV002Schema{
		Message:   msg,
		Data:      &models.CoseV002SchemaData{},
		PublicKey: p(pub),
	}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := v.IndexKeys()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Preimage digest indexed under its declared algorithm.
	mustContain(t, "sha256:"+hex.EncodeToString(digest[:]), got)
}

func mustContain(t *testing.T, want string, l []string) {
	t.Helper()
	for _, s := range l {
		if s == want {
			return
		}
	}
	t.Fatalf("list %v does not contain %s", l, want)
}
