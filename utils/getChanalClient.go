package utils

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"traceGo/preDefine"
)

var sdk *fabsdk.FabricSDK
var channalClient *channel.Client
var err error

func getSDKandChannelClient() (*fabsdk.FabricSDK, *channel.Client, error) {
	sdk, err = fabsdk.New(config.FromFile(preDefine.YamlPath))
	if err != nil {
		return nil, nil, err
	}
	ctx := sdk.ChannelContext(preDefine.ChannalID, fabsdk.WithUser("Admin"))
	channalClient, err = channel.New(ctx)
	if err != nil {
		sdk.Close()
		return nil, nil, err
	}
	return sdk, channalClient, err
}
