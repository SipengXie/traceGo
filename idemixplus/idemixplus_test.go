package idemixplus

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/stretchr/testify/assert"
)

func TestIdemixplus(t *testing.T) {
	//// Test KeyGen
	rng := GetRand(32)
	// Test idemixplus functionality
	AttributeNames := []string{"Attr1", "Attr2", "Attr3", "Attr4", "Attr5"}
	attrs := make([]*FP256BN.BIG, len(AttributeNames))
	for i := range AttributeNames {
		attrs[i] = FP256BN.NewBIGint(i)
	}

	// Test issuer key generation
	//if err != nil {
	//	t.Fatalf("Error getting rng: \"%s\"", err)
	//	return
	//}
	// Create a new key pair
	keys, err := NewIssuerKey(AttributeNames, rng)

	keyBytes, _ := proto.Marshal(keys)
	if err != nil {
		fmt.Println(err)
	}
	encodeString := base64.StdEncoding.EncodeToString(keyBytes)
	fmt.Println("****" + encodeString)
	key := &IssuerKey{}
	decodeBytes, _ := base64.StdEncoding.DecodeString(encodeString)
	proto.Unmarshal(decodeBytes, key)

	if err != nil {
		t.Fatalf("Issuer key generation should have succeeded but gave error \"%s\"", err)
		return
	}
	// Check that the key is valid
	err = key.GetIpk().Check()
	if err != nil {
		t.Fatalf("Issuer public key should be valid")
		return
	}

	var userDuration int64 = 0
	var creDuration int64 = 0
	var sigDuration int64 = 0
	var verDuration int64 = 0
	var traceDuration int64 = 0
	for i := 0; i < 1; i++ {
		// Test issuance
		startTime := time.Now().UnixNano()
		AttributeNames1 := []string{"a", "Ab", "t3", "t4", "r"}
		ukey, trace, err := NewUserKey(AttributeNames1, rng)
		if err != nil {
			t.Fatalf("Issuer key generation should have succeeded but gave error \"%s\"", err)
			return
		}
		keyBytes, _ := proto.Marshal(trace)
		if err != nil {
			fmt.Println(err)
		}
		traceEncodeString := base64.StdEncoding.EncodeToString(keyBytes)
		fmt.Println(traceEncodeString)
		// Check that the key is valid
		err = ukey.GetUpk().Check()
		if err != nil {
			t.Fatalf("Issuer public key should be valid")
			return
		}

		userTime := time.Now().UnixNano()
		// Test create credential request
		usk := FP256BN.FromBytes(ukey.GetUsk().GetX())
		ni := RandModOrder(rng)
		m := NewCredRequest(usk, BigToBytes(ni), key.Ipk, rng)

		// the Issuer chech the request from user
		traces := new(Traces)
		traces.TraceList = append(traces.TraceList, trace)
		cred, err := NewCredential(key, m, ukey.Upk, attrs, rng)
		assert.NoError(t, err, "Failed to issue a credentoal: \"%s\"", err)
		assert.NoError(t, cred.Ver(usk, key.Ipk), "credential should be valid")

		creTime := time.Now().UnixNano()
		// Generate a nymCredential
		nymattrs := []byte{1, 1, 1, 0, 1}
		msg := []byte("hello world")
		msg1 := []byte("hello world1")
		nymcred, err := NewNymSignature(usk, cred, key.Ipk, msg, nymattrs, nil, rng)
		assert.NoError(t, err)
		sigTime := time.Now().UnixNano()
		assert.NoError(t, nymcred.Ver(key.GetIpk(), msg1, nil, 0))
		verTime := time.Now().UnixNano()
		// Test arbitration
		upk, err := Arbitration(traces, nymcred)
		assert.NoError(t, err)
		assert.Equal(t, upk, ukey.GetUpk(), "Not the same")

		traceTime := time.Now().UnixNano()

		userDuration += userTime - startTime
		creDuration += creTime - userTime
		sigDuration += sigTime - creTime
		verDuration += verTime - sigTime
		traceDuration += traceTime - verTime
	}
	fmt.Println("-----------------------------------------")
	fmt.Println("total running times: 500")
	fmt.Println("-----------------------------------------")
	fmt.Printf("time of registering user: %d ms\n", userDuration/1000000/500)
	fmt.Printf("time of generating the cert: %d ms\n", creDuration/1000000/500)
	fmt.Printf("time of signing: %d ms\n", sigDuration/1000000/500)
	fmt.Printf("time of verifing tehe signature: %d ms\n", verDuration/1000000/500)
	fmt.Printf("time of tracing: %d ms\n", traceDuration/1000000/500)
	fmt.Println("-----------------------------------------")
	fmt.Println("*****************E N D*******************")
	fmt.Println("-----------------------------------------")
}
