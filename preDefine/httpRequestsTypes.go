package preDefine

// ZJ requests
type InitRequest struct {
	User         string   `json:"user"`
	Attributions []string `json:"attributions"`
	Sed          int      `json:"sed"`
}

type UserInfoRequest struct {
	User  string `json:"user"`
	Trace string `json:"trace"`
}

type CreateCredentialRequestRequest struct {
	User string `json:"user"`
	Pri  string `json:"pri"`
}

type CreateCredentialRequest struct {
	User string `json:"user"`
	Cr   string `json:"cr"`
}

type CredentialTraceRequest struct {
	Sig           string `json:"sig"`
	TransactionID string `json:"transactionID"`
}

type VerifyRequest struct {
	User   string `json:"user"`
	Msg    string `json:"msg"`
	Random string `json:"random"`
}

// Confidential requests

type ReceiverStruct struct {
	Name string `json:"name"`
}

type SendConfidentialMessageRequest struct {
	Sender      string           `json:"sender"`
	Receiver    []ReceiverStruct `json:"receiver"`
	SendType    string           `json:"sendType"`
	Message     string           `json:"message"`
	FileMessage string           `json:"fileMessage"`
}

type GetMessageStruct struct {
	Id      int    `json:"id"`
	Sender  string `json:"sender"`
	Type    string `json:"type"`
	Time    string `json:"time"`
	Content string `json:"content"`
	Url     string `json:"url"`
}

type GetConfidentialMessageRequest struct {
	Messages []GetMessageStruct `json:"messages"`
}

// trace requests

type UploadContentRequest struct {
	Content []byte `json:"Content"`
}

type QueryContentRequest struct {
	Txid string `json:"txid"`
}
