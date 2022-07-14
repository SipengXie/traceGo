package idemixplus

import (
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

//Arbitration is arbitrating the anonymous credential by CA
func Arbitration(traces *Traces, anonymity *NymSignature) (*UserPublicKey, error) {
	if traces == nil || anonymity == nil {
		return nil, errors.Errorf("Cannot Arbitration AnonymousCredential: received nil input")
	}

	Eta := EcpFromProto(anonymity.GetEta())
	Xi := EcpFromProto(anonymity.GetXi())

	for _, trace := range traces.TraceList {
		t := Ecp2FromProto(trace.GetT())
		left := FP256BN.Fexp(FP256BN.Ate(GenG2, Eta))
		right := FP256BN.Fexp(FP256BN.Ate(t, Xi))

		if left.Equals(right) {
			return trace.GetUpk(), nil
		}

	}

	return nil, errors.Errorf("Not find the user")
}
