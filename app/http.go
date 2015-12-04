package certinel

import (
	"encoding/json"
	"net/http"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
)

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

func StartAPIServer(port string) {
	router := mux.NewRouter()

	api := router.PathPrefix("/api").Subrouter()
	api = api.StrictSlash(true)
	api.Path("/domains").Methods("PUT").HandlerFunc(addDomain)
	api.Path("/domains").Methods("GET").HandlerFunc(getDomains)

	n := negroni.New(negroni.NewRecovery())
	n.UseHandler(router)
	n.Run(":" + port)
}
