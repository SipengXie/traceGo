package idemixplus

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

func hiddenIndices(Disclosure []byte) []int {
	HiddenIndices := make([]int, 0)
	for index, disclose := range Disclosure {
		if disclose == 0 {
			HiddenIndices = append(HiddenIndices, index)
		}
	}
	return HiddenIndices
}

func isIn(arr []int, value int) bool {
	for _, v := range arr {
		if v == value {
			return true
		}
	}
	return false
}

// NewNymSignature creates signature
func NewNymSignature(sk *FP256BN.BIG, cred *Credential, ipk *IssuerPublicKey, msg []byte, disclosure []byte, cri *CredentialRevocationInformation, rng *amcl.RAND) (*NymSignature, error) {
	fmt.Println("NewNymSignature", string(msg))
	// Validate inputs
	if sk == nil || cred == nil || ipk == nil || disclosure == nil || rng == nil {
		return nil, errors.Errorf("cannot create NewNymSignature: received nil input")
	}

	// Sample the randomness needed for the proof
	u := RandModOrder(rng)
	v := RandModOrder(rng)
	nonce := RandModOrder(rng)

	Xi := GenG1.Mul(u)
	Eta := Xi.Mul(sk)

	nymSign := new(NymSignature)

	nymSign.Eta = EcpToProto(Eta)
	nymSign.Xi = EcpToProto(Xi)
	nymSign.Nonce = BigToBytes(nonce)

	HiddenIndices := hiddenIndices(disclosure)
	for index := range cred.Creds {
		if isIn(HiddenIndices, index) {
			hide := new(HiddenAttribute)
			Sigma1 := EcpFromProto(cred.Creds[index].A).Mul(v)
			Sigma2 := EcpFromProto(cred.Creds[index].B).Mul(v)
			Sigma3 := Sigma1.Mul(sk)

			hide.Sigma_1 = EcpToProto(Sigma1)
			hide.Sigma_2 = EcpToProto(Sigma2)
			hide.Sigma_3 = EcpToProto(Sigma3)

			a := RandModOrder(rng)
			t1 := Sigma1.Mul(a)
			t2 := Xi.Mul(a)

			proofData := make([]byte, 18*FieldBytes+3+len(msg))
			i := 0
			i = appendBytesG1(proofData, i, t1)
			i = appendBytesG1(proofData, i, t2)
			i = appendBytesG1(proofData, i, Sigma1)
			i = appendBytesG1(proofData, i, Xi)
			i = appendBytesG1(proofData, i, Sigma3)
			i = appendBytesG1(proofData, i, Eta)

			// for signature
			i = appendBytes(proofData, i, msg)

			Ca := HashModOrder(proofData)

			C := make([]byte, len(BigToBytes(Ca))+len(BigToBytes(nonce)))
			i = 0
			i = appendBytes(C, i, BigToBytes(Ca))
			i = appendBytes(C, i, BigToBytes(nonce))
			c := HashModOrder(C)

			Sa := Modadd(a, FP256BN.Modmul(c, sk, GroupOrder), GroupOrder)

			hide.ProofC = BigToBytes(c)
			hide.ProofS = BigToBytes(Sa)

			nymSign.Hides = append(nymSign.Hides, hide)
		} else {
			nymSign.Attrs = append(nymSign.Attrs, cred.Attrs[index])
		}

	}

	if cri != nil {
		nymSign.RevocationEpochPk = cri.EpochPk
		nymSign.RevocationPkSig = cri.EpochPkSig
		nymSign.Epoch = cri.Epoch
	}

	return nymSign, nil
}

// Ver verifies an idemix NymSignature
// modify at 2020-03-12 16:09:53
// delete the parameter: sk
func (nym *NymSignature) Ver(ipk *IssuerPublicKey, msg []byte, revPk *ecdsa.PublicKey, epoch int) error {
	fmt.Println("NewNymSignature Ver", string(msg))
	Hides := nym.GetHides()

	Eta := EcpFromProto(nym.GetEta())
	Xi := EcpFromProto(nym.GetXi())
	Nonce := nym.Nonce

	for _, hide := range Hides {
		Sigma1 := EcpFromProto(hide.GetSigma_1())
		Sigma2 := EcpFromProto(hide.GetSigma_2())
		Sigma3 := EcpFromProto(hide.GetSigma_3())
		ProofC := FP256BN.FromBytes(hide.GetProofC())
		ProofS := FP256BN.FromBytes(hide.GetProofS())

		t1 := Sigma1.Mul(ProofS)
		t1.Add(Sigma3.Mul(FP256BN.Modneg(ProofC, GroupOrder)))

		t2 := Xi.Mul(ProofS)
		t2.Add(Eta.Mul(FP256BN.Modneg(ProofC, GroupOrder)))

		proofData := make([]byte, 18*FieldBytes+3+len(msg))
		i := 0
		i = appendBytesG1(proofData, i, t1)
		i = appendBytesG1(proofData, i, t2)
		i = appendBytesG1(proofData, i, Sigma1)
		i = appendBytesG1(proofData, i, Xi)
		i = appendBytesG1(proofData, i, Sigma3)
		i = appendBytesG1(proofData, i, Eta)
		i = appendBytes(proofData, i, msg)
		Ca := HashModOrder(proofData)

		C := make([]byte, len(BigToBytes(Ca))+len(Nonce))
		i = 0
		i = appendBytes(C, i, BigToBytes(Ca))
		i = appendBytes(C, i, Nonce)

		if *ProofC != *HashModOrder(C) {
			return errors.Errorf("NymSignature is not fit with the Issuer PublicKey")
		}

		left := FP256BN.Ate(Ecp2FromProto(ipk.GetBarX()), Sigma1)
		left.Mul(FP256BN.Ate(Ecp2FromProto(ipk.GetBarY()), Sigma3))
		left = FP256BN.Fexp(left)
		right := FP256BN.Fexp(FP256BN.Ate(GenG2, Sigma2))
		if !left.Equals(right) {
			return errors.Errorf("NymSignature is not fit with the NymSignature format")
		}
	}

	return nil
}
