package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/greengrass"
)

type Config struct {
	Region string // optional
	Name   string // optional

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
	sess := session.Must(session.NewSession(awscfg))

	//svc := greengrass.New(sess, aws.NewConfig().WithRegion("us-west-2"))
	svc := greengrass.New(sess)
	c, err := svc.CreateCoreDefinition(&greengrass.CreateCoreDefinitionInput{
		//AmznClientToken: &cfg.Token,
		Name: &cfg.Name,
	})
	fmt.Println(c)
	fmt.Println()
	fmt.Println(err)
}
