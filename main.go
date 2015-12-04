package main

import (
	"flag"
	"log"

	"github.com/drtoful/certinel/app"
)

func main() {
	dbPath := flag.String("db", "certinel.db", "path to the database store")
	httpPort := flag.String("port", "8080", "port for api server")

	if err := certinel.StoreInit(*dbPath); err != nil {
		log.Fatal(err)
	}

	certinel.StartDomainChecker()
	certinel.StartAPIServer(*httpPort)
}
