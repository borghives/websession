package websession

import (
	"log"
	"net/http"
)

func ListenAndServe(handler http.Handler) {
	log.Print("starting server...")

	hostInfo := GetHostInfo()
	log.Printf("START New Host Instance@%s Build:%s Image:%s ", hostInfo.ID, hostInfo.BuildId, hostInfo.ImageId)

	Manager() // initialize session manager fatal if secret not found

	// Determine port for HTTP service.
	port := CollapseConstants().Port

	// Start HTTP server.
	log.Printf("listening on port %s", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}
