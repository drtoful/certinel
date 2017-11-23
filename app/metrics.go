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
	currentProvider MetricProvider
)

type providerPrometheus struct {
	certificateExpiration *prometheus.GaugeVec
	certificateSuccess    *prometheus.CounterVec
	certificateError      *prometheus.CounterVec
}

func newProviderPrometheus() *providerPrometheus {
	result := &providerPrometheus{}
	result.certificateExpiration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "certificate_expiration",
			Help: "Time to certifiate expiration in seconds",
		},
		[]string{"domain", "port"},
	)
	result.certificateSuccess = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "certificate_success",
			Help: "Count of successes retrieving certificate",
		},
		[]string{"domain", "port"},
	)
	result.certificateError = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "certificate_error",
			Help: "Count of errors retrieving certificate",
		},
		[]string{"domain", "port"},
	)

	prometheus.MustRegister(result.certificateExpiration)
	prometheus.MustRegister(result.certificateSuccess)
	prometheus.MustRegister(result.certificateError)

	return result
}

func (p *providerPrometheus) AddMetricError(domain, port string, e error) {
	p.certificateError.With(prometheus.Labels{"domain": domain, "port": port}).Inc()
}

func (p *providerPrometheus) AddMetric(domain, port string, validity float64) {
	p.certificateExpiration.With(prometheus.Labels{"domain": domain, "port": port}).Set(validity)
	p.certificateSuccess.With(prometheus.Labels{"domain": domain, "port": port}).Inc()
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
	switch mtype {
	case "prometheus":
		currentProvider = newProviderPrometheus()
		break
	}

	if currentProvider != nil {
		log.Printf("starting metrics server on %s\n", maddress)
		n := negroni.New(negroni.NewRecovery())
		n.UseHandler(currentProvider.GetRouter())
		go n.Run(maddress)
	}
}
