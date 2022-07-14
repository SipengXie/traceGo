/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemixplus

import (
	"fmt"
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

// Identity Mixer Credential is a list of attributes certified (signed) by the issuer
// A credential also contains a user secret key blindly signed by the issuer
// Without the secret key the credential cannot be used

// Credential issuance is an interactive protocol between a user and an issuer
// The issuer takes its secret and public keys and user attribute values as input
// The user takes the issuer public key and user secret as input
// The issuance protocol consists of the following steps:
// 1) The issuer sends a random nonce to the user
// 2) The user creates a Credential Request using the public key of the issuer, user secret, and the nonce as input
//    The request consists of a commitment to the user secret (can be seen as a public key) and a zero-knowledge proof
//     of knowledge of the user secret key
//    The user sends the credential request to the issuer
// 3) The issuer verifies the credential request by verifying the zero-knowledge proof
//    If the request is valid, the issuer issues a credential to the user by signing the commitment to the secret key
//    together with the attribute values and sends the credential back to the user
// 4) The user verifies the issuer's signature and stores the credential that consists of
//    the signature value, a randomness used to create the signature, the user secret, and the attribute values

// NewCredential issues a new credential, which is the last step of the interactive issuance protocol
// All attribute values are added by the issuer at this step and then signed together with a commitment to
// the user's secret key from a credential request
func NewCredential(key *IssuerKey, m *CredRequest, upk *UserPublicKey, attrs []*FP256BN.BIG, rng *amcl.RAND) (*Credential, error) {
	fmt.Println("NewCredential")
	if attrs == nil || rng == nil || key == nil {
		return nil, errors.Errorf("cannot create NewCredential: received nil input")
	}

	if len(attrs) != len(upk.AttributeNames) {
		return nil, errors.Errorf("incorrect number of attribute values passed")
	}

	err := m.Check(key.Ipk)
	if err != nil {
		return nil, err
	}

	creds := new(Credential)
	// The signature is now generated.
	for index, attribute := range attrs {
		r := RandModOrder(rng)
		signed := new(SignedAttribute)
		signed.A = EcpToProto(GenG1.Mul(r))

		signed.B = EcpToProto(GenG1.Mul(r).Mul2(FP256BN.FromBytes(key.Isk.X), EcpFromProto(upk.UPK).Mul(r), FP256BN.FromBytes(key.Isk.Y)))

		creds.Creds = append(creds.Creds, signed)
		creds.Attrs = append(creds.Attrs, BigToBytes(attribute))
		creds.AttributeNames = append(creds.AttributeNames, key.Ipk.AttributeNames[index])
	}
	return creds, nil
}

//Ver checks the credential is valid
func (cred *Credential) Ver(sk *FP256BN.BIG, ipk *IssuerPublicKey) error {
	fmt.Println("NewCredential  Ver")
	// Validate Input

	if len(cred.Attrs) == 0 {
		return errors.Errorf("credential has no value for attribute")
	}

	// - parse the credential
	for i, attr := range cred.Attrs {
		if attr == nil {
			return errors.Errorf("credential has no value for attribute %s", cred.AttributeNames[i])
		}
	}
	for i, signedAttr := range cred.Creds {
		A := EcpFromProto(signedAttr.A)
		B := EcpFromProto(signedAttr.B)

		BarY := Ecp2FromProto(ipk.BarY).Mul(sk)
		BarY.Add(Ecp2FromProto(ipk.BarX))
		BarY.Affine()
		left := FP256BN.Fexp(FP256BN.Ate(BarY, A))
		right := FP256BN.Fexp(FP256BN.Ate(GenG2, B))

		if !left.Equals(right) {
			return errors.Errorf("credential is not cryptographically valid %s", ipk.AttributeNames[i])
		}
	}

	return nil
}
