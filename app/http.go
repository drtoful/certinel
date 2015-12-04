package certinel

import (
	"encoding/json"
	"errors"
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

	data, err := json.Marshal(domains)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func getDomainStatus(w http.ResponseWriter, r *http.Request) {
	domain, err := parseDomain(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	status, err := domain.Status()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	data, err := json.Marshal(status)
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
		Current string   `json:"current"`
		History []string `json:"history"`
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

func StartAPIServer(port string) {
	router := mux.NewRouter()

	api := router.PathPrefix("/api").Subrouter()
	api = api.StrictSlash(true)
	api.Path("/domains").Methods("PUT").HandlerFunc(addDomain)
	api.Path("/domains").Methods("GET").HandlerFunc(getDomains)
	api.Path("/d/status").Methods("GET").HandlerFunc(getDomainStatus)
	api.Path("/d/certs").Methods("GET").HandlerFunc(getDomainCerts)

	n := negroni.New(negroni.NewRecovery())
	n.UseHandler(router)
	n.Run(":" + port)
}
