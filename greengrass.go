package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/greengrass"
	"github.com/aws/aws-sdk-go/service/iot"
)

type Config struct {
	Region string
	Name   string
}

type Thing struct {
	CaPath   string `json:"caPath"`
	CertPath string `json:"certPath"`
	KeyPath  string `json:"keyPath"`
	ThingArn string `json:"thingArn"`
	IotHost  string `json:"iotHost"`
	GgHost   string `json:"ggHost"`
}

type cgroup struct {
	UseSystemd string `json:"useSystemd"`
}

type runtime struct {
	cgroup `json:"cgroup"`
}

type CoreConfig struct {
	CoreThing Thing   `json:"coreThing"`
	Runtime   runtime `json:"runtime"`
}

func exitWithError(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func (c *Config) Load() error {
	flag.StringVar(&c.Region, "region", "", "AWS Region the Greengrass is in")
	flag.StringVar(&c.Name, "name", "", "GreenGrass Core Name")
	flag.Parse()

	return nil
}

func main() {
	fmt.Println("GreenGrass Auto Deploy")

	// Create a Greengrass client with additional configuration
	cfg := Config{}
	if err := cfg.Load(); err != nil {
		exitWithError(fmt.Errorf("failed to load config, %v", err))
	}

	awscfg := &aws.Config{}
	awscfg.Credentials = credentials.NewEnvCredentials()
	if len(cfg.Region) > 0 {
		awscfg.WithRegion(cfg.Region)
	}
	gg_core_name := cfg.Name + "_core"
	gg_group_name := cfg.Name + "_group"
	gg_policy_name := cfg.Name + "_policy"

	sess := session.Must(session.NewSession(awscfg))

	iot_svc := iot.New(sess)
	gg_svc := greengrass.New(sess)

	csrTmpl := &x509.CertificateRequest{}
	csrTmpl.Subject.CommonName = "NXP DCCA IOT"
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	var keyPem bytes.Buffer
	pem.Encode(&keyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	err = ioutil.WriteFile("/greengrass/certs/gg_core_priv.key", keyPem.Bytes(), 0644)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Create Certificate Request")
	csrData, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		fmt.Println(err)
	}
	pemBuf := bytes.NewBuffer(nil)
	pem.Encode(pemBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrData})

	cert, err := iot_svc.CreateCertificateFromCsr(&iot.CreateCertificateFromCsrInput{
		CertificateSigningRequest: aws.String(pemBuf.String()),
		SetAsActive:               aws.Bool(true),
	})
	if err != nil {
		fmt.Println(err)
	}
	err = ioutil.WriteFile("/greengrass/certs/gg_core_cert.pem", []byte(*cert.CertificatePem), 0644)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(*cert.CertificateArn)

	ct, err := iot_svc.CreateThing(&iot.CreateThingInput{
		ThingName: &gg_core_name,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	doc := `{"Version":"2012-10-17","Statement": [{"Effect": "Allow","Action": ["iot:Publish","iot:Subscribe","iot:Connect","iot:Receive"],"Resource": ["*"]},{"Effect": "Allow","Action": ["iot:GetThingShadow","iot:UpdateThingShadow","iot:DeleteThingShadow"],"Resource": ["*"]},{"Effect": "Allow","Action": ["greengrass:*"],"Resource": ["*"]}]}`

	_, err = iot_svc.CreatePolicy(&iot.CreatePolicyInput{
		PolicyDocument: &doc,
		PolicyName:     &gg_policy_name})
	if err != nil {
		fmt.Println(err)
	}
	_, err = iot_svc.AttachPrincipalPolicy(&iot.AttachPrincipalPolicyInput{
		PolicyName: &gg_policy_name,
		Principal:  cert.CertificateArn})
	if err != nil {
		fmt.Println(err)
	}

	_, err = iot_svc.AttachThingPrincipal(&iot.AttachThingPrincipalInput{
		Principal: cert.CertificateArn,
		ThingName: ct.ThingName,
	})
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Create GreenGrass Core Definition")
	cc, err := gg_svc.CreateCoreDefinition(&greengrass.CreateCoreDefinitionInput{
		Name: &gg_core_name,
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Creating New Core")
	fmt.Println(*cc.Arn)

	cores := make([]*greengrass.Core, 1)
	core := &greengrass.Core{
		Id:             cc.Id,
		ThingArn:       ct.ThingArn,
		CertificateArn: cert.CertificateArn,
		SyncShadow:     aws.Bool(true),
	}
	cores[0] = core

	fmt.Println("Create GreenGrass Core Definition Version")
	cv, err := gg_svc.CreateCoreDefinitionVersion(&greengrass.CreateCoreDefinitionVersionInput{
		CoreDefinitionId: cc.Id,
		Cores:            cores,
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(*cv.Arn)

	fmt.Println("Create GreenGrass Function Definition")
	cf, err := gg_svc.CreateFunctionDefinition(&greengrass.CreateFunctionDefinitionInput{
		Name: &cfg.Name,
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(*cf.Arn)

	fmt.Println("Create GreenGrass Function Configuration")
	func_conf := &greengrass.FunctionConfiguration{
		Executable: aws.String("messageLambda.message_handler"),
		MemorySize: aws.Int64(1024),
		Timeout:    aws.Int64(10),
	}

	lfuncs := make([]*greengrass.Function, 1)
	lfunc := &greengrass.Function{
		FunctionArn: cf.Arn,
		Id:          cc.Id,
		FunctionConfiguration: func_conf,
	}
	lfuncs[0] = lfunc

	fmt.Println("Create Group")
	cg, err := gg_svc.CreateGroup(&greengrass.CreateGroupInput{
		Name: &gg_group_name,
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(*cg.Arn)

	fmt.Println("Create Group Version")
	gv, err := gg_svc.CreateGroupVersion(&greengrass.CreateGroupVersionInput{
		CoreDefinitionVersionArn: cv.Arn,
		GroupId:                  cg.Id,
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(gv.Arn)

	ced, err := iot_svc.DescribeEndpoint(&iot.DescribeEndpointInput{})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Core EndPoint: ", *ced.EndpointAddress)

	gg_config := &CoreConfig{
		CoreThing: Thing{
			CaPath:   "rootCA.pem",
			CertPath: "gg_core_cert.pem",
			KeyPath:  "gg_core_priv.key",
			ThingArn: *ct.ThingArn,
			IotHost:  *ced.EndpointAddress,
			GgHost:   fmt.Sprintf("greengrass.iot.%s.amazonaws.com", cfg.Region),
		},
		Runtime: runtime{
			cgroup: cgroup{
				UseSystemd: "no",
			},
		},
	}

	b, err := json.Marshal(gg_config)
	fmt.Println("Writing GreenGrass Configuration")
	if err != nil {
		fmt.Println("error:", err)
	}
	ioutil.WriteFile("/greengrass/config/config.json", b, 0644)

}
