package preDefine

// ZJ responses
type CreateCredentialRequestResponse struct {
	Code  string `json:"code"`
	Msg   string `json:"msg"`
	Cr    string `json:"cr"`
	Spend int64  `json:"spend"`
}

type CreateCredentialResponse struct {
	Code  string `json:"code"`
	Msg   string `json:"msg"`
	Cred  string `json:"cred"`
	Spend int64  `json:"spend"`
}

type CredentialTraceResponse struct {
	Code  string `json:"code"`
	Msg   string `json:"msg"`
	Pub   string `json:"pub"`
	Spend int64  `json:"spend"`
}

type IssuerKeyResponse struct {
	Code  string `json:"code"`
	Msg   string `json:"msg"`
	Pub   string `json:"pub"`
	Pri   string `json:"pri"`
	Spend int64  `json:"spend"`
}

type AttributionsResponse struct {
	Code         string   `json:"code"`
	Msg          string   `json:"msg"`
	Attributions []string `json:"attributions"`
}

type UserKeyResponse struct {
	Code  string `json:"code"`
	Msg   string `json:"msg"`
	Pub   string `json:"pub"`
	Pri   string `json:"pri"`
	Trace string `json:"trace"`
	Spend int64  `json:"spend"`
}

type VerifyResponse struct {
	Code  string `json:"code"`
	Msg   string `json:"msg"`
	Spend int64  `json:"spend"`
}

// Confidential Response

type ReadConfidentialResponse struct {
	Code     string   `json:"code"`
	Spend    int64    `json:"spend"`
	Messages [][]byte `json:"messages"`
	Notes    []string `json:"notes"`
}

// Trace response

type UploadResponse struct {
	Code  string `json:"code"`
	Spend int64  `json:"spend"`
	Msg   string `json:"content"`
}

type QueryContentResponse struct {
	Code    string `json:"code"`
	Spend   int64  `json:"spend"`
	Content []byte `json:"content"`
}
