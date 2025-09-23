package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	hits := cfg.fileserverHits.Load()
	fmt.Fprintf(w, `
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, hits)
}

func (cfg *apiConfig) handlerResetHits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	cfg.fileserverHits.Store(0)
	w.Write([]byte("OK"))
}

func handlerHealthz(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func handlerRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/app/", http.StatusMovedPermanently)
}

func main() {
	apiCfg := new(apiConfig)
	fServer := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	sMux := http.NewServeMux()
	sMux.Handle("/app/", apiCfg.middlewareMetricsInc(fServer))
	sMux.HandleFunc("/app", handlerRedirect)
	sMux.HandleFunc("GET /api/healthz", handlerHealthz)
	sMux.HandleFunc("GET /admin/metrics", apiCfg.handlerAdmin)
	sMux.HandleFunc("POST /admin/reset", apiCfg.handlerResetHits)
	server := &http.Server{
		Addr:    ":8080",
		Handler: sMux,
	}
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error: %v", err)
	}
}
