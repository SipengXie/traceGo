package utils

import (
	"fmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/gopackager"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"os"
)

// Chaincode installation
func InstallCC(org, user, path, gopath, chanincodeid, version string, sdk *fabsdk.FabricSDK) (*resmgmt.Client, error) {
	client, err := msp.New(sdk.Context(), msp.WithOrg(org))

	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	userIdentigy, err := client.GetSigningIdentity(user)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	userclientcontent := sdk.Context(fabsdk.WithIdentity(userIdentigy))
	resclient, err := resmgmt.New(userclientcontent)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	ccPkg, err := gopackager.NewCCPackage(path, gopath)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	ccreq := resmgmt.InstallCCRequest{
		Name:    chanincodeid,
		Version: version,
		Path:    path,
		Package: ccPkg,
	}
	responses, err := resclient.InstallCC(ccreq, resmgmt.WithRetry(retry.DefaultResMgmtOpts))
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	fmt.Println(responses)
	return resclient, nil
}
