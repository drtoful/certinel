package certinel

import (
	"log"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type MetricProvider interface {
	AddMetric(domain, port string, validity float64)
	AddMetricError(domain, port string, e error)
	GetRouter() *mux.Router
}

var (
	promCertificateExpiration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "certificate_expiration",
			Help: "Time to certifiate expiration in seconds",
		},
		[]string{"domain", "port"},
	)
	promCertificateSuccess = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "certificate_success",
			Help: "Count of successes retrieving certificate",
		},
		[]string{"domain", "port"},
	)
	promCertificateError = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "certificate_error",
			Help: "Count of errors retrieving certificate",
		},
		[]string{"domain", "port"},
	)

	currentProvider MetricProvider
)

func init() {
	prometheus.MustRegister(promCertificateExpiration)
	prometheus.MustRegister(promCertificateSuccess)
	prometheus.MustRegister(promCertificateError)
}

type providerPrometheus struct {
}

func (p *providerPrometheus) AddMetricError(domain, port string, e error) {
	promCertificateError.With(prometheus.Labels{"domain": domain, "port": port}).Inc()
}

func (p *providerPrometheus) AddMetric(domain, port string, validity float64) {
	promCertificateExpiration.With(prometheus.Labels{"domain": domain, "port": port}).Set(validity)
	promCertificateSuccess.With(prometheus.Labels{"domain": domain, "port": port}).Inc()
}

func (p *providerPrometheus) GetRouter() *mux.Router {
	router := mux.NewRouter()
	router.Path("/metrics").Methods("GET").HandlerFunc(promhttp.Handler().ServeHTTP)
	return router
}

func AddMetricPoint(domain, port string, validity float64, e error) {
	// delegate to currently running metric provider
	if currentProvider != nil {
		if e != nil {
			currentProvider.AddMetricError(domain, port, e)
		} else {
			currentProvider.AddMetric(domain, port, validity)
		}
	}
}

func StartMetricsServer(mtype, maddress string) {
	log.Println(mtype)
	log.Println(maddress)
	switch mtype {
	case "prometheus":
		currentProvider = &providerPrometheus{}
		break
	}

	if currentProvider != nil {
		n := negroni.New(negroni.NewRecovery())
		n.UseHandler(currentProvider.GetRouter())
		go n.Run(maddress)
	}
}
