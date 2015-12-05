package certinel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
)

var (
	ErrInvalidArgument = errors.New("invalid argument")
)

func parseDomain(r *http.Request) (*Domain, error) {
	values := r.URL.Query()
	d, ok := values["domain"]
	if !ok || len(d) == 0 || len(d[0]) == 0 {
		return nil, ErrInvalidArgument
	}

	p, ok := values["port"]
	if !ok || len(p) == 0 || len(p[0]) == 0 {
		return nil, ErrInvalidArgument
	}

	domain := &Domain{Domain: d[0], Port: p[0]}
	return domain, nil
}

func addDomain(w http.ResponseWriter, r *http.Request) {
	var req Domain

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	if len(req.Domain) == 0 || len(req.Port) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing data"))
		return
	}

	// start new domain checker
	go CheckDomain(req.Domain, req.Port)
	w.WriteHeader(http.StatusOK)
}

func getDomains(w http.ResponseWriter, r *http.Request) {
	domains := GetDomains()
	type _domain struct {
		Domain string  `json:"domain"`
		Port   string  `json:"port"`
		Status *Status `json:"status"`
	}
	type _result struct {
		Valid   int        `json:"valid"`
		Invalid int        `json:"invalid"`
		Domains []*_domain `json:"domains"`
	}

	result := make([]*_domain, 0)
	valid := 0
	invalid := 0
	for _, d := range domains {
		status, err := d.Status()
		if err != nil {
			continue
		}
		result = append(result, &_domain{
			Domain: d.Domain,
			Port:   d.Port,
			Status: status,
		})
		if status.Valid {
			valid += 1
		} else {
			invalid += 1
		}
	}

	data, err := json.Marshal(_result{
		Valid:   valid,
		Invalid: invalid,
		Domains: result,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func getDomainCerts(w http.ResponseWriter, r *http.Request) {
	domain, err := parseDomain(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	current, history, err := domain.CertList()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	type _json struct {
		Current *Certificate   `json:"current"`
		History []*Certificate `json:"history,omitempty"`
	}
	value := &_json{Current: current, History: history}

	data, err := json.Marshal(value)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	data, err := Asset("static/index.html")
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", data)
}

func StartAPIServer(port string) {
	router := mux.NewRouter()

	api := router.PathPrefix("/api").Subrouter()
	api = api.StrictSlash(true)
	api.Path("/domains").Methods("PUT").HandlerFunc(addDomain)
	api.Path("/domains").Methods("GET").HandlerFunc(getDomains)
	api.Path("/certs").Methods("GET").HandlerFunc(getDomainCerts)

	router.Path("/").Methods("GET").HandlerFunc(getIndex)

	n := negroni.New(negroni.NewRecovery())
	n.UseHandler(router)
	n.Run(":" + port)
}
