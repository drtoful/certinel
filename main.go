package main

import (
	"flag"
	"log"

	"github.com/drtoful/certinel/app"
)

func main() {
	dbPath := flag.String("db", "certinel.db", "path to the database store")

	if err := certinel.StoreInit(*dbPath); err != nil {
		log.Fatal(err)
	}
}
