package certinel

import (
	"encoding/json"
	"net/http"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
)

func addDomain(w http.ResponseWriter, r *http.Request) {
	type _json struct {
		Domain string `json:"domain"`
		Port   string `json:"port"`
	}
	var req _json

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

func StartAPIServer(port string) {
	router := mux.NewRouter()

	api := router.PathPrefix("/api").Subrouter()
	api = api.StrictSlash(true)
	api.Path("/domains").Methods("PUT").HandlerFunc(addDomain)

	n := negroni.New(negroni.NewRecovery())
	n.UseHandler(router)
	n.Run(":" + port)
}
