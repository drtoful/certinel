package main

//go:generate go-bindata -o app/bindata.go -pkg "certinel" static/...

import (
	"flag"
	"log"

	"github.com/drtoful/certinel/app"
)

func main() {
	var (
		dbPath   = flag.String("db", "certinel.db", "path to the database store")
		httpPort = flag.String("port", "8080", "port for api server")
	)
	flag.Parse()

	if err := certinel.StoreInit(*dbPath); err != nil {
		log.Fatal(err)
	}

	certinel.StartDomainChecker()
	certinel.StartAPIServer(*httpPort)
}
