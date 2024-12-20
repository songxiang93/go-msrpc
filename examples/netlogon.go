package main

// netlogon.go script gets the domain info from the remote server.
import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"os"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/nrpc/logon/v1"
	"github.com/rs/zerolog"

	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

func init() {
	// add credentials.
	os.Setenv("SERVER", "******************")
	os.Setenv("USERNAME", "*********************")
	os.Setenv("PASSWORD", "***************")
	gssapi.AddCredential(credential.NewFromPassword(os.Getenv("USERNAME"), os.Getenv("PASSWORD")))
	// add mechanism.
	//gssapi.AddMechanism(ssp.SPNEGO)
	gssapi.AddMechanism(ssp.NTLM)
}

func j(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func main() {

	ctx := gssapi.NewSecurityContext(context.Background())

	addr := os.Getenv("SERVER")
	opt := epm.EndpointMapper(ctx, addr, dcerpc.WithLogger(zerolog.New(os.Stdout)))
	cc, err := dcerpc.Dial(ctx, addr, dcerpc.WithLogger(zerolog.New(os.Stdout)), opt)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	cli, err := logon.NewLogonClient(ctx, cc, dcerpc.WithSign())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	//resp, err := cli.AccountDeltas(ctx, &logon.AccountDeltasRequest{})
	//if err != nil {
	//	panic(err)
	//} else {
	//	fmt.Println(resp)
	//}
	//resp, err := cli.GetDomainInfo(ctx, &logon.GetDomainInfoRequest{})
	//if err != nil {
	//	panic(err)
	//} else {
	//	fmt.Println(resp)
	//}

	resp, err := cli.GetDCName(ctx, &logon.GetDCNameRequest{
		ComputerName: "PC$",
		Flags:        logon.DSReturnDNSName | logon.DSIPRequired,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)

	} else {
		fmt.Printf("%s\n", j(resp.DomainControllerInfo))
	}

	// do valid call.
	//trusts, err := cli.EnumerateDomainTrusts(ctx, &logon.EnumerateDomainTrustsRequest{
	//	ServerName: "dc1",
	//	Flags:      logon.TrustTypeForestMember,
	//})
	//if err != nil {
	//
	//	fmt.Println(j(trusts))
	//	fmt.Fprintln(os.Stderr, err)
	//	return
	//}
	//
	//for _, dom := range trusts.Domains.Domains {
	//	fmt.Println(j(dom))
	//}

}
