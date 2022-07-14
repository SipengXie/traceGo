package httpHandler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"log"
	"net/http"
	"time"
	"traceGo/idemixplus"
	"traceGo/preDefine"
	"traceGo/utils"
)

type UserInfo struct {
	Pub          string   `json:"pub"`
	Pri          string   `json:"pri"`
	Trace        string   `json:"trace"`
	Attributions []string `json:"attributions"`
	Cr           string   `json:"cr"`
	Cred         string   `json:"cred"`
	Random       string   `json:"random"`
}

type UserTraceInfo struct {
	Pub          string   `json:"pub"`
	User         string   `json:"user"`
	Attributions []string `json:"attributions"`
}

type Record struct {
	NymCred []byte `json:"nymcred"`
	Content string `json:"content"`
}

var Rng = idemixplus.GetRand(32)
var Attrs []*FP256BN.BIG
var traces = new(idemixplus.Traces)
var issuerKey *idemixplus.IssuerKey
var attributions []string
var UserInfoMap = make(map[string]UserInfo)
var UserTraceInfoArray []UserTraceInfo

// ZJ init issuer

func InitIssuer(writer http.ResponseWriter, request *http.Request) {
	var result preDefine.IssuerKeyResponse
	defer func() {
		_ = json.NewEncoder(writer).Encode(result)
	}()
	var initIssuerRequest preDefine.InitRequest
	if err := json.NewDecoder(request.Body).Decode(&initIssuerRequest); err != nil {
		_ = request.Body.Close()
		result.Code = "400"
		result.Msg = "解码失败"
		return
	}
	st := time.Now()
	IssuerKey, err := idemixplus.NewIssuerKey(initIssuerRequest.Attributions, Rng)
	if err != nil {
		result.Code = "400"
		result.Msg = "初始化失败"
		return
	}
	spend := time.Now().Sub(st).Nanoseconds()

	Attrs = make([]*FP256BN.BIG, len(initIssuerRequest.Attributions))
	for i := range initIssuerRequest.Attributions {
		Attrs[i] = FP256BN.NewBIGint(i)
	}

	ipkBytes, _ := proto.Marshal(IssuerKey.Ipk)
	_, err = utils.ExecuteCC(preDefine.ZJCCID, "ipkinit", [][]byte{ipkBytes}, channalClient)
	if err != nil {
		fmt.Println(err)
		return
	}
	priKeyBytes, _ := proto.Marshal(IssuerKey.Isk)
	pubKeyBytes, _ := proto.Marshal(IssuerKey.Ipk)
	priEncodeString := base64.StdEncoding.EncodeToString(priKeyBytes)
	pubEncodeString := base64.StdEncoding.EncodeToString(pubKeyBytes)
	result.Code = "200"
	result.Msg = "初始化成功"
	result.Pri = priEncodeString
	result.Pub = pubEncodeString
	result.Spend = spend
	issuerKey = IssuerKey
	attributions = initIssuerRequest.Attributions
	UserInfoMap["CA"] = UserInfo{
		Pub: pubEncodeString,
	}
}

func GetAttributions(writer http.ResponseWriter, request *http.Request) {
	var result preDefine.AttributionsResponse
	defer func() {
		_ = json.NewEncoder(writer).Encode(result)
	}()
	if attributions == nil {
		result.Code = "400"
		result.Msg = "CA尚未初始化"
	}
	result.Code = "200"
	result.Msg = "初始化成功"
	result.Attributions = attributions
}

func InitUser(writer http.ResponseWriter, request *http.Request) {
	var result preDefine.UserKeyResponse
	defer func() {
		_ = json.NewEncoder(writer).Encode(result)
	}()
	var initUserRequest preDefine.InitRequest
	if err := json.NewDecoder(request.Body).Decode(&initUserRequest); err != nil {
		_ = request.Body.Close()
		result.Code = "400"
		result.Msg = fmt.Sprintf("%v", err)
		return
	}
	start := time.Now()
	keys, trace, err := idemixplus.NewUserKey(initUserRequest.Attributions, Rng)
	spend := time.Now().Sub(start).Nanoseconds()
	if err != nil {
		result.Code = "400"
		result.Msg = fmt.Sprintf("%v", err)
		return
	}
	priKeyBytes, _ := proto.Marshal(keys.Usk)
	pubKeyBytes, _ := proto.Marshal(keys.Upk)
	traceBytes, _ := proto.Marshal(trace)
	priEncodeString := base64.StdEncoding.EncodeToString(priKeyBytes)
	pubEncodeString := base64.StdEncoding.EncodeToString(pubKeyBytes)
	traceEncodeString := base64.StdEncoding.EncodeToString(traceBytes)
	result.Code = "200"
	result.Msg = "初始化成功"
	result.Pri = priEncodeString
	result.Pub = pubEncodeString
	result.Trace = traceEncodeString
	result.Spend = spend
	traces.TraceList = append(traces.TraceList, trace)
	UserInfoMap[initUserRequest.User] = UserInfo{
		Pri:          priEncodeString,
		Pub:          pubEncodeString,
		Trace:        traceEncodeString,
		Attributions: initUserRequest.Attributions,
	}
	UserTraceInfoArray = append(UserTraceInfoArray, UserTraceInfo{
		User:         initUserRequest.User,
		Pub:          pubEncodeString,
		Attributions: initUserRequest.Attributions,
	})
}

func GetUserInfo(writer http.ResponseWriter, request *http.Request) {
	var userInfoRequest preDefine.UserInfoRequest
	if err := json.NewDecoder(request.Body).Decode(&userInfoRequest); err != nil {
		_ = request.Body.Close()
		return
	}
	if userInfoRequest.Trace == "" {
		var result UserInfo
		result = UserInfoMap[userInfoRequest.User]
		_ = json.NewEncoder(writer).Encode(result)
		return
	}
	if userInfoRequest.Trace == "trace" {
		_ = json.NewEncoder(writer).Encode(UserTraceInfoArray)
	}
}

func CreateCredentialRequest(writer http.ResponseWriter, request *http.Request) {
	var result preDefine.CreateCredentialRequestResponse
	defer func() {
		_ = json.NewEncoder(writer).Encode(result)
	}()
	var createCredentialRequestRequest preDefine.CreateCredentialRequestRequest
	if err := json.NewDecoder(request.Body).Decode(&createCredentialRequestRequest); err != nil {
		_ = request.Body.Close()
		return
	}

	start := time.Now()
	pri := &idemixplus.UserSecretKey{}
	decodeBytes, _ := base64.StdEncoding.DecodeString(createCredentialRequestRequest.Pri)
	spend := time.Now().Sub(start).Nanoseconds()
	_ = proto.Unmarshal(decodeBytes, pri)

	usk := FP256BN.FromBytes(pri.X)
	ni := idemixplus.RandModOrder(Rng)
	cr := idemixplus.NewCredRequest(usk, idemixplus.BigToBytes(ni), issuerKey.Ipk, Rng)
	crBytes, _ := proto.Marshal(cr)
	crEncodeString := base64.StdEncoding.EncodeToString(crBytes)
	userInfo := UserInfoMap[createCredentialRequestRequest.User]
	userInfo.Cr = crEncodeString
	UserInfoMap[createCredentialRequestRequest.User] = userInfo
	result.Code = "200"
	result.Spend = spend
	result.Msg = "证书请求创建成功"
	result.Cr = crEncodeString
}

func CreateCredential(writer http.ResponseWriter, request *http.Request) {
	var result preDefine.CreateCredentialResponse
	defer func() {
		_ = json.NewEncoder(writer).Encode(result)
	}()
	var createCredentialRequest preDefine.CreateCredentialRequest
	if err := json.NewDecoder(request.Body).Decode(&createCredentialRequest); err != nil {
		_ = request.Body.Close()
		return
	}
	start := time.Now()
	cr := &idemixplus.CredRequest{}
	decodeBytes, _ := base64.StdEncoding.DecodeString(createCredentialRequest.Cr)
	spend := time.Now().Sub(start).Nanoseconds()
	_ = proto.Unmarshal(decodeBytes, cr)

	upk := &idemixplus.UserPublicKey{}
	decodeBytes, _ = base64.StdEncoding.DecodeString(UserInfoMap[createCredentialRequest.User].Pub)
	_ = proto.Unmarshal(decodeBytes, upk)

	cred, err := idemixplus.NewCredential(issuerKey, cr, upk, Attrs, Rng)
	if err != nil {
		result.Code = "400"
		result.Msg = fmt.Sprintf("%v", err)
		return
	}
	usk := &idemixplus.UserSecretKey{}
	decodeBytes, _ = base64.StdEncoding.DecodeString(UserInfoMap[createCredentialRequest.User].Pri)
	_ = proto.Unmarshal(decodeBytes, usk)
	err = cred.Ver(FP256BN.FromBytes(usk.GetX()), issuerKey.Ipk)
	if err != nil {
		log.Fatal(err)
	}

	credBytes, _ := proto.Marshal(cred)
	credEncodeString := base64.StdEncoding.EncodeToString(credBytes)

	userInfo := UserInfoMap[createCredentialRequest.User]
	userInfo.Cred = credEncodeString
	UserInfoMap[createCredentialRequest.User] = userInfo
	result.Code = "200"
	result.Msg = "证书请求创建成功"
	result.Cred = credEncodeString
	result.Spend = spend
}

func Verify(writer http.ResponseWriter, request *http.Request) {
	var result preDefine.VerifyResponse
	defer func() {
		_ = json.NewEncoder(writer).Encode(result)
	}()
	var verifyRequest preDefine.VerifyRequest
	if err := json.NewDecoder(request.Body).Decode(&verifyRequest); err != nil {
		_ = request.Body.Close()
		return
	}

	sig := &idemixplus.NymSignature{}
	decodeBytes, _ := base64.StdEncoding.DecodeString(verifyRequest.Random)
	_ = proto.Unmarshal(decodeBytes, sig)
	start := time.Now()
	err := sig.Ver(issuerKey.Ipk, []byte(verifyRequest.Msg), nil, 0)
	spend := time.Now().Sub(start).Nanoseconds()
	if err != nil {
		result.Code = "200"
		result.Msg = "fail"
		return
	}
	result.Code = "200"
	result.Msg = "success"
	result.Spend = spend
}

func Trace(writer http.ResponseWriter, request *http.Request) {
	var result preDefine.CredentialTraceResponse
	defer func() {
		_ = json.NewEncoder(writer).Encode(result)
	}()
	var traceRequest preDefine.CredentialTraceRequest
	if err := json.NewDecoder(request.Body).Decode(&traceRequest); err != nil {
		_ = request.Body.Close()
		return
	}
	sig := &idemixplus.NymSignature{}
	start := time.Now()

	upk := &idemixplus.UserPublicKey{}
	if traceRequest.Sig != "" {
		decodeBytes, _ := base64.StdEncoding.DecodeString(traceRequest.Sig)
		_ = proto.Unmarshal(decodeBytes, sig)

		var err error
		upk, err = idemixplus.Arbitration(traces, sig)
		if err != nil {
			result.Code = "400"
			result.Msg = "追踪失败"
		}
	} else {
		fmt.Println("=================链上追踪开始===================")
		fmt.Println(traceRequest.TransactionID)
		queryArgs := [][]byte{[]byte(traceRequest.TransactionID)}
		response, err := utils.ExecuteCC(preDefine.ZJCCID, "queryIdemix", queryArgs, channalClient)
		if err != nil {
			fmt.Println(err)
			return
		}
		record := &Record{}
		err = json.Unmarshal(response.Payload, record)
		if err != nil {
			fmt.Println(err)
			return
		}
		nymSignature := &idemixplus.NymSignature{}
		err = proto.Unmarshal(record.NymCred, nymSignature)
		// fmt.Println(nymBlock)
		upk, err = idemixplus.Arbitration(traces, nymSignature)
		if err != nil {
			result.Code = "400"
			result.Msg = "追踪失败"
		}
	}

	spend := time.Now().Sub(start).Nanoseconds()

	result.Code = "200"
	result.Msg = "证书请求创建成功"
	upkBytes, _ := proto.Marshal(upk)
	upkEncodeString := base64.StdEncoding.EncodeToString(upkBytes)
	result.Pub = upkEncodeString
	result.Spend = spend
}
