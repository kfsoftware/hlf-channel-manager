/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package main

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/core/logging/modlog"
	"github.com/kfsoftware/hlf-channel-manager/cmd"
	"github.com/kfsoftware/hlf-channel-manager/log"
)

func main() {
	modlog.InitLogger(log.HLFLoggerProvider{})
	rootCMD := cmd.NewRootCMD()
	err := rootCMD.Execute()
	if err != nil {
		panic(err)
	}
}
