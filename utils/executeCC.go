package utils

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
)

// Chaincode execution layer

func ExecuteCC(CCID, Fcn string, Args [][]byte, channalClient *channel.Client) (channel.Response, error) {
	resp, err := channalClient.Execute(channel.Request{ChaincodeID: CCID, Fcn: Fcn, Args: Args}, channel.WithRetry(retry.DefaultChannelOpts))
	return resp, err
}
