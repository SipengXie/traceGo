package httpHandler

import "github.com/hyperledger/fabric-sdk-go/pkg/client/channel"

var channalClient *channel.Client

func SetClient(client *channel.Client) {
	channalClient = client
}
