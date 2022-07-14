package httpHandler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"traceGo/preDefine"
	"traceGo/utils"
)

func UploadMessage(writer http.ResponseWriter, request *http.Request) {
	var result preDefine.UploadResponse
	defer func() {
		_ = json.NewEncoder(writer).Encode(result)
	}()
	var uploadRequest preDefine.UploadContentRequest
	if err := json.NewDecoder(request.Body).Decode(&uploadRequest); err != nil {
		_ = request.Body.Close()
		return
	}
	start := time.Now()
	args := [][]byte{uploadRequest.Content}
	response, err := utils.ExecuteCC(preDefine.TRCCID, "recordContent", args, channalClient)
	if err != nil {
		result.Code = "400"
		result.Msg = err.Error()
		fmt.Println(err)
		return
	}
	spend := time.Now().Sub(start).Nanoseconds()
	result.Code = "200"
	result.Spend = spend
	result.Msg = string(response.TransactionID)
}

func QueryMessage(writer http.ResponseWriter, request *http.Request) {
	var result preDefine.QueryContentResponse
	defer func() {
		_ = json.NewEncoder(writer).Encode(result)
	}()
	var queryRequest preDefine.QueryContentRequest
	if err := json.NewDecoder(request.Body).Decode(&queryRequest); err != nil {
		_ = request.Body.Close()
		return
	}
	start := time.Now()
	args := [][]byte{[]byte(queryRequest.Txid)}
	response, err := utils.ExecuteCC(preDefine.TRCCID, "queryContent", args, channalClient)
	if err != nil {
		result.Code = "400"
		fmt.Println(err)
		return
	}
	spend := time.Now().Sub(start).Nanoseconds()
	result.Code = "200"
	result.Spend = spend
	result.Content = response.Payload
}
