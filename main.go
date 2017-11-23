package main

//go:generate go-bindata -o app/bindata.go -pkg "certinel" static/...

import (
	"flag"
	"log"

	"github.com/drtoful/certinel/app"
)

func main() {
	var (
		dbPath      = flag.String("db", "certinel.db", "path to the database store")
		httpPort    = flag.String("port", "8080", "port for api server")
		metricsType = flag.String("metrics.type", "prometheus", "type of metrics server to start")
		metricsBind = flag.String("metrics.bind", "127.0.0.1:9090", "host:port on where to bind the metrics to")
	)
	flag.Parse()

	if err := certinel.StoreInit(*dbPath); err != nil {
		log.Fatal(err)
	}

	certinel.StartDomainChecker()
	certinel.StartMetricsServer(*metricsType, *metricsBind)
	certinel.StartAPIServer(*httpPort)
}
