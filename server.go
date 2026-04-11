package websession

import (
	"log"
	"net/http"
)

func ListenAndServeHost(handler http.Handler) {
	log.Print("starting server...")

	hostInfo := GetHostInfo()
	log.Printf("START New Host Instance@%s Build:%s Image:%s ", hostInfo.ID, hostInfo.BuildId, hostInfo.ImageId)

	Manager() // initialize session manager fatal if secret not found

	// Determine port for HTTP service.
	port := CollapseConstants().Port

	// Start HTTP server.  Check Host header is allowed
	log.Printf("listening on port %s", port)
	if err := http.ListenAndServe(":"+port, RequestCheckAllowHost(handler)); err != nil {
		log.Fatal(err)
	}
}

// RequestCheckAllowHost checks if the request's Host header is in the allowed list
func RequestCheckAllowHost(next http.Handler) http.Handler {
	var allowedHosts = GetAllowedHosts()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := allowedHosts[r.Host]; !ok {
			log.Printf("Forbidden host: %s", r.Host)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func RequestCheckAllowOnlyReadMethod(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			log.Printf("Method not allowed: %s", r.Method)
			http.Error(w, "Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		next.ServeHTTP(w, r)
	})
}
