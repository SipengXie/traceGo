/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemixplus

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

// The Issuer secret ISk and public IPk keys are used to issue credentials and
// to verify signatures created using the credentials

// The Issuer Secret Key is a random exponent (generated randomly from Z*_p)

// The Issuer Public Key consists of several elliptic curve points (ECP),
// where index 1 corresponds to group G1 and 2 to group G2)
// HSk, HRand, BarG1, BarG2, and an ECP2 W,
// and a proof of knowledge of the corresponding secret key

// NewIssuerKey creates a new issuer key pair taking an array of attribute names
// that will be contained in credentials certified by this issuer (a credential specification)
// See http://eprint.iacr.org/2016/663.pdf Sec. 4.3, for references.
func NewIssuerKey(AttributeNames []string, rng *amcl.RAND) (*IssuerKey, error) {
	fmt.Println("NewIssuerKey")
	// validate inputs

	// check for duplicated attributes
	attributeNamesMap := map[string]bool{}
	for _, name := range AttributeNames {
		if attributeNamesMap[name] {
			return nil, errors.Errorf("attribute %s appears multiple times in AttributeNames", name)
		}
		attributeNamesMap[name] = true
	}

	key := new(IssuerKey)
	isk := new(SecretKey)

	// generate issuer secret key
	x := RandModOrder(rng)
	y := RandModOrder(rng)
	isk.X = BigToBytes(x)
	isk.Y = BigToBytes(y)
	key.Isk = isk

	// generate the corresponding public key
	key.Ipk = new(IssuerPublicKey)
	key.Ipk.AttributeNames = AttributeNames

	BarX := GenG2.Mul(x)
	key.Ipk.BarX = Ecp2ToProto(BarX)

	BarY := GenG2.Mul(y)
	key.Ipk.BarY = Ecp2ToProto(BarY)

	// generate base for the secret key
	HSk := GenG1.Mul(RandModOrder(rng))
	key.Ipk.HSk = EcpToProto(HSk)

	// generate base for the randomness
	HRand := GenG1.Mul(RandModOrder(rng))
	key.Ipk.HRand = EcpToProto(HRand)

	BarG1 := GenG1.Mul(RandModOrder(rng))
	key.Ipk.BarG1 = EcpToProto(BarG1)

	BarG2 := BarG1.Mul(x)
	key.Ipk.BarG2 = EcpToProto(BarG2)

	BarG3 := BarG1.Mul(y)
	key.Ipk.BarG3 = EcpToProto(BarG3)

	// generate a zero-knowledge proof of knowledge (ZK PoK) of the secret key which
	// is in W and BarG2.

	// Sample the randomness needed for the proof
	r1 := RandModOrder(rng)
	r2 := RandModOrder(rng)

	// Step 1: First message (t-values)
	t11 := GenG2.Mul(r1) // t1 = g_2^r, cover W
	t12 := BarG1.Mul(r1) // t2 = (\bar g_1)^r, cover BarG2

	t21 := GenG2.Mul(r2)
	t22 := BarG1.Mul(r2)

	// Step 2: Compute the Fiat-Shamir hash, forming the challenge of the ZKP.
	proofData := make([]byte, 18*FieldBytes+3)
	index := 0
	index = appendBytesG2(proofData, index, t11)
	index = appendBytesG1(proofData, index, t12)
	index = appendBytesG2(proofData, index, GenG2)
	index = appendBytesG1(proofData, index, BarG1)
	index = appendBytesG2(proofData, index, BarX)
	index = appendBytesG1(proofData, index, BarG2)

	proofCX := HashModOrder(proofData)
	key.Ipk.ProofCX = BigToBytes(proofCX)

	// Step 3: reply to the challenge message (s-values)
	proofSX := Modadd(FP256BN.Modmul(proofCX, x, GroupOrder), r1, GroupOrder) // // s = r + C \cdot ISk
	key.Ipk.ProofSX = BigToBytes(proofSX)

	proofDataY := make([]byte, 18*FieldBytes+3)
	index = 0
	index = appendBytesG2(proofDataY, index, t21)
	index = appendBytesG1(proofDataY, index, t22)
	index = appendBytesG2(proofDataY, index, GenG2)
	index = appendBytesG1(proofDataY, index, BarG1)
	index = appendBytesG2(proofDataY, index, BarY)
	index = appendBytesG1(proofDataY, index, BarG3)

	proofCY := HashModOrder(proofDataY)
	key.Ipk.ProofCY = BigToBytes(proofCY)

	proofSY := Modadd(FP256BN.Modmul(proofCY, y, GroupOrder), r2, GroupOrder)
	key.Ipk.ProofSY = BigToBytes(proofSY)

	// Hash the public key
	serializedIPk, err := proto.Marshal(key.Ipk)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal issuer public key")
	}
	key.Ipk.Hash = BigToBytes(HashModOrder(serializedIPk))
	// We are done
	return key, nil
}

// Check checks that this issuer public key is valid, i.e.
// that all components are present and a ZK proofs verifies
func (IPk *IssuerPublicKey) Check() error {
	fmt.Println("NewIssuerKey Check")
	// Unmarshall the public key
	NumAttrs := len(IPk.GetAttributeNames())
	HSk := EcpFromProto(IPk.GetHSk())
	HRand := EcpFromProto(IPk.GetHRand())
	BarG1 := EcpFromProto(IPk.GetBarG1())
	BarG2 := EcpFromProto(IPk.GetBarG2())
	BarG3 := EcpFromProto(IPk.GetBarG3())
	BarX := Ecp2FromProto(IPk.GetBarX())
	BarY := Ecp2FromProto(IPk.GetBarY())
	ProofCX := FP256BN.FromBytes(IPk.GetProofCX())
	ProofSX := FP256BN.FromBytes(IPk.GetProofSX())
	ProofCY := FP256BN.FromBytes(IPk.GetProofCY())
	ProofSY := FP256BN.FromBytes(IPk.GetProofSY())

	// Check that the public key is well-formed
	if NumAttrs < 0 ||
		HSk == nil ||
		HRand == nil ||
		BarG1 == nil ||
		BarG1.Is_infinity() ||
		BarG2 == nil ||
		BarG3 == nil {
		return errors.Errorf("some part of the public key is undefined")
	}

	// Verify Proof

	// Recompute challenge
	proofData := make([]byte, 18*FieldBytes+3)
	index := 0

	// Recompute t-values using s-values
	t11 := GenG2.Mul(ProofSX)
	t11.Add(BarX.Mul(FP256BN.Modneg(ProofCX, GroupOrder))) // t1 = g_2^s \cdot W^{-C}

	t12 := BarG1.Mul(ProofSX)
	t12.Add(BarG2.Mul(FP256BN.Modneg(ProofCX, GroupOrder))) // t2 = {\bar g_1}^s \cdot {\bar g_2}^C

	index = appendBytesG2(proofData, index, t11)
	index = appendBytesG1(proofData, index, t12)
	index = appendBytesG2(proofData, index, GenG2)
	index = appendBytesG1(proofData, index, BarG1)
	index = appendBytesG2(proofData, index, BarX)
	index = appendBytesG1(proofData, index, BarG2)

	proofDataY := make([]byte, 18*FieldBytes+3)
	index = 0

	// Recompute t-values using s-values
	t21 := GenG2.Mul(ProofSY)
	t21.Add(BarY.Mul(FP256BN.Modneg(ProofCY, GroupOrder))) // t1 = g_2^s \cdot W^{-C}

	t22 := BarG1.Mul(ProofSY)
	t22.Add(BarG3.Mul(FP256BN.Modneg(ProofCY, GroupOrder))) // t2 = {\bar g_1}^s \cdot {\bar g_2}^C

	index = appendBytesG2(proofDataY, index, t21)
	index = appendBytesG1(proofDataY, index, t22)
	index = appendBytesG2(proofDataY, index, GenG2)
	index = appendBytesG1(proofDataY, index, BarG1)
	index = appendBytesG2(proofDataY, index, BarY)
	index = appendBytesG1(proofDataY, index, BarG3)

	// Verify that the challenge is the same
	if *ProofCX != *HashModOrder(proofData) || *ProofCY != *HashModOrder(proofDataY) {
		return errors.Errorf("zero knowledge proof in public key invalid")
	}

	return IPk.SetHash()
}

// SetHash appends a hash of a serialized public key
func (IPk *IssuerPublicKey) SetHash() error {
	IPk.Hash = nil
	serializedIPk, err := proto.Marshal(IPk)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal issuer public key")
	}
	IPk.Hash = BigToBytes(HashModOrder(serializedIPk))
	return nil
}

// NewUserKey creates a new user key pair taking an array of attribute names
func NewUserKey(AttributeNames []string, rng *amcl.RAND) (*UserKey, *Trace, error) {
	fmt.Println("NewUserKey")
	// validate inputs

	// check for duplicated attributes
	attributeNamesMap := map[string]bool{}
	for _, name := range AttributeNames {
		if attributeNamesMap[name] {
			return nil, nil, errors.Errorf("attribute %s appears multiple times in AttributeNames", name)
		}
		attributeNamesMap[name] = true
	}

	key := new(UserKey)
	trace := new(Trace)

	// generate issuer secret key
	USk := RandModOrder(rng)
	key.Usk = new(UserSecretKey)
	key.Usk.X = BigToBytes(USk)

	// generate the corresponding public key
	key.Upk = new(UserPublicKey)
	key.Upk.AttributeNames = AttributeNames
	key.Upk.UPK = EcpToProto(GenG1.Mul(USk))

	W := GenG2.Mul(USk)
	key.Upk.W = Ecp2ToProto(W)

	// generate base for the secret key
	HSk := GenG1.Mul(RandModOrder(rng))
	key.Upk.HSk = EcpToProto(HSk)

	// generate base for the randomness
	HRand := GenG1.Mul(RandModOrder(rng))
	key.Upk.HRand = EcpToProto(HRand)

	BarG1 := GenG1.Mul(RandModOrder(rng))
	key.Upk.BarG1 = EcpToProto(BarG1)

	BarG2 := BarG1.Mul(USk)
	key.Upk.BarG2 = EcpToProto(BarG2)

	// generate a zero-knowledge proof of knowledge (ZK PoK) of the secret key which
	// is in W and BarG2.

	// Sample the randomness needed for the proof
	r := RandModOrder(rng)

	// Step 1: First message (t-values)
	t1 := GenG2.Mul(r) // t1 = g_2^r, cover W
	t2 := BarG1.Mul(r) // t2 = (\bar g_1)^r, cover BarG2

	// Step 2: Compute the Fiat-Shamir hash, forming the challenge of the ZKP.
	proofData := make([]byte, 18*FieldBytes+3)
	index := 0
	index = appendBytesG2(proofData, index, t1)
	index = appendBytesG1(proofData, index, t2)
	index = appendBytesG2(proofData, index, GenG2)
	index = appendBytesG1(proofData, index, BarG1)
	index = appendBytesG2(proofData, index, W)
	index = appendBytesG1(proofData, index, BarG2)

	proofC := HashModOrder(proofData)
	key.Upk.ProofC = BigToBytes(proofC)

	// Step 3: reply to the challenge message (s-values)
	proofS := Modadd(FP256BN.Modmul(proofC, USk, GroupOrder), r, GroupOrder) // // s = r + C \cdot ISk
	key.Upk.ProofS = BigToBytes(proofS)

	// Hash the public key
	serializedUPk, err := proto.Marshal(key.Upk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to marshal issuer public key")
	}
	key.Upk.Hash = BigToBytes(HashModOrder(serializedUPk))

	// Generate a Trace
	trace.T = Ecp2ToProto(GenG2.Mul(USk))
	trace.Upk = key.Upk
	// We are done
	return key, trace, nil
}

// Check checks that this user public key is valid, i.e.
// that all components are present and a ZK proofs verifies
func (UPk *UserPublicKey) Check() error {
	fmt.Println("NewUserKey Check")
	// Unmarshall the public key
	NumAttrs := len(UPk.GetAttributeNames())
	HSk := EcpFromProto(UPk.GetHSk())
	HRand := EcpFromProto(UPk.GetHRand())
	BarG1 := EcpFromProto(UPk.GetBarG1())
	BarG2 := EcpFromProto(UPk.GetBarG2())
	W := Ecp2FromProto(UPk.GetW())
	ProofC := FP256BN.FromBytes(UPk.GetProofC())
	ProofS := FP256BN.FromBytes(UPk.GetProofS())

	// Check that the public key is well-formed
	if NumAttrs < 0 ||
		HSk == nil ||
		HRand == nil ||
		BarG1 == nil ||
		BarG1.Is_infinity() ||
		BarG2 == nil {
		return errors.Errorf("some part of the public key is undefined")
	}

	// Verify Proof

	// Recompute challenge
	proofData := make([]byte, 18*FieldBytes+3)
	index := 0

	// Recompute t-values using s-values
	t1 := GenG2.Mul(ProofS)
	t1.Add(W.Mul(FP256BN.Modneg(ProofC, GroupOrder))) // t1 = g_2^s \cdot W^{-C}

	t2 := BarG1.Mul(ProofS)
	t2.Add(BarG2.Mul(FP256BN.Modneg(ProofC, GroupOrder))) // t2 = {\bar g_1}^s \cdot {\bar g_2}^C

	index = appendBytesG2(proofData, index, t1)
	index = appendBytesG1(proofData, index, t2)
	index = appendBytesG2(proofData, index, GenG2)
	index = appendBytesG1(proofData, index, BarG1)
	index = appendBytesG2(proofData, index, W)
	index = appendBytesG1(proofData, index, BarG2)

	// Verify that the challenge is the same
	if *ProofC != *HashModOrder(proofData) {
		return errors.Errorf("zero knowledge proof in public key invalid")
	}

	return UPk.SetHash()
}

// SetHash appends a hash of a serialized public key
func (UPk *UserPublicKey) SetHash() error {
	UPk.Hash = nil
	serializedUPk, err := proto.Marshal(UPk)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal issuer public key")
	}
	UPk.Hash = BigToBytes(HashModOrder(serializedUPk))
	return nil
}

func (UPK UserPublicKey) Bytes() ([]byte, error) {
	// TODO
	return nil, nil
}

func (UPK UserSecretKey) Bytes() ([]byte, error) {
	// TODO
	return nil, nil
}
