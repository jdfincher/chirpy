package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jdfincher/chirpy/internal/auth"
	"github.com/jdfincher/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	secret         string
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerAddUser(w http.ResponseWriter, r *http.Request) {
	type userParams struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := new(userParams)

	if err := decoder.Decode(params); err != nil {
		log.Printf("Error: issue decoding json: %s", err)
	}
	hPass, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("Error: password was not hashed properly: %s", err)
	}
	dbParams := database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hPass,
	}
	dbuser, err := cfg.db.CreateUser(r.Context(), dbParams)
	if err != nil {
		log.Printf("Error: issue creating database record for user: %s", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	u := User{
		ID:        dbuser.ID,
		CreatedAt: dbuser.CreatedAt,
		UpdatedAt: dbuser.UpdatedAt,
		Email:     dbuser.Email,
	}
	data, err := json.Marshal(u)
	if err != nil {
		log.Printf("Error: issue marshalling struct: %s", err)
	}
	w.Write(data)
}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	type userLogin struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	uLogin := new(userLogin)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(uLogin); err != nil {
		log.Printf("Error: issue decoding request: %s", err)
	}

	userDB, err := cfg.db.FindUserByEmail(r.Context(), uLogin.Email)
	if err != nil {
		_ = userDB
		w.WriteHeader(401)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `
<html>
			<body>
				<h1>Incorrect email or password</h1>
			</body>
</html>`+"\n")
		return
	}

	err = auth.CheckPassHash(uLogin.Password, userDB.HashedPassword)
	if err != nil {
		_ = userDB
		w.WriteHeader(401)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "Incorrect email or password\n")
		return
	}

	lifeSpan := time.Duration(3600) * time.Second
	tokenString, err := auth.MakeJWT(userDB.ID, cfg.secret, lifeSpan)
	if err != nil {
		log.Printf("Error: issue creating JWT: %s\n", err)
	}

	type userOut struct {
		ID           uuid.UUID `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
	}
	uOut := userOut{
		ID:           userDB.ID,
		CreatedAt:    userDB.CreatedAt,
		UpdatedAt:    userDB.UpdatedAt,
		Email:        userDB.Email,
		Token:        tokenString,
		RefreshToken: auth.MakeRefreshToken(),
	}

	if err := cfg.db.RecordRefreshToken(r.Context(), database.RecordRefreshTokenParams{
		Token:  uOut.RefreshToken,
		UserID: uOut.ID,
	}); err != nil {
		log.Printf("Error: issue recording refresh token in database: %s\n", err)
	}
	data, err := json.Marshal(uOut)
	if err != nil {
		log.Printf("Error: issue marshalling response data: %s\n", err)
	}
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
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
</html>`+"\n", hits)
}

func (cfg *apiConfig) handlerRefreshToken(w http.ResponseWriter, r *http.Request) {
	refTokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(401)
		return
	}
	refToken, err := cfg.db.CheckRefreshToken(r.Context(), refTokenString)
	if err != nil {
		w.WriteHeader(401)
		return
	}
	ok := refToken.ExpiresAt.After(time.Now())
	if !ok || refToken.RevokedAt.Valid {
		w.WriteHeader(401)
		return
	}
	tokenString, err := auth.MakeJWT(refToken.UserID, cfg.secret, time.Duration(3600)*time.Second)
	if err != nil {
		log.Printf("Error: could not issue new JWT: %s", err)
	}
	type tokenOut struct {
		Token string `json:"token"`
	}
	tOut := tokenOut{
		Token: tokenString,
	}
	data, err := json.Marshal(tOut)
	if err != nil {
		log.Printf("Error: issue marshalling response data: %s", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) handlerRevokeToken(w http.ResponseWriter, r *http.Request) {
	refTokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(401)
		return
	}
	if err := cfg.db.RevokeToken(r.Context(), refTokenString); err != nil {
		w.WriteHeader(401)
		return
	}
	w.WriteHeader(204)
}

func (cfg *apiConfig) handlerResetHits(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		w.WriteHeader(403)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	cfg.fileserverHits.Store(0)
	cfg.db.ClearUsers(r.Context())
	w.Write([]byte("OK"))
}

func handlerHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func handlerRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/app/", http.StatusMovedPermanently)
}

func (cfg *apiConfig) handlerGetChirpByID(w http.ResponseWriter, r *http.Request) {
	CID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		log.Printf("Error: issue parsing chirp id from path: %s\n", err)
	}
	c, err := cfg.db.GetChirpByID(r.Context(), CID)
	if err != nil {
		log.Printf("Error: issue retrieving chirp from database: %s\n", err)
		w.WriteHeader(404)
		return
	}
	type chirp struct {
		Body      string    `json:"body"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		ID        uuid.UUID `json:"id"`
		UserID    uuid.UUID `json:"user_id"`
	}
	fchirp := chirp{
		Body:      c.Body,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
		ID:        c.ID,
		UserID:    c.UserID,
	}
	data, err := json.Marshal(&fchirp)
	if err != nil {
		log.Printf("Error: issue marshalling response data: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) handlerGetAllChirps(w http.ResponseWriter, r *http.Request) {
	type chirpOutParams struct {
		Body      string    `json:"body"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		ID        uuid.UUID `json:"id"`
		UserID    uuid.UUID `json:"user_id"`
	}
	chirpsdb, err := cfg.db.GetAllChirps(r.Context())
	if err != nil {
		w.WriteHeader(404)
		log.Printf("Error: issue retrieving chirps from db : %s", err)
		return
	}
	chirpsOut := make([]chirpOutParams, len(chirpsdb))

	for i, c := range chirpsdb {
		chirpsOut[i] = chirpOutParams{
			Body:      c.Body,
			CreatedAt: c.CreatedAt,
			UpdatedAt: c.UpdatedAt,
			ID:        c.ID,
			UserID:    c.UserID,
		}
	}
	data, err := json.Marshal(chirpsOut)
	if err != nil {
		w.WriteHeader(400)
		log.Printf("Error: issue marshalling data for response: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(data)
}

func (cfg *apiConfig) handlerChirps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		cfg.handlerGetAllChirps(w, r)
	case "POST":
		type chirpParams struct {
			Body  string `json:"body"`
			Token string `json:"token"`
		}
		decoder := json.NewDecoder(r.Body)
		params := new(chirpParams)

		if err := decoder.Decode(params); err != nil {
			log.Printf("Error: issue decoding request:%s", err)
		}
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("%s", err)
			w.WriteHeader(401)
			return
		}
		id, err := auth.ValidateJWT(token, cfg.secret)
		if err != nil {
			log.Printf("%s", err)
			w.WriteHeader(401)
			return
		}

		if len(params.Body) > 140 {
			params.Body = "Error: chirp over max 140 character length"
			w.WriteHeader(400)
			data, err := json.Marshal(params)
			if err != nil {
				log.Printf("Error: issue marshalling response data: %s", err)
			}
			w.Write(data)
			return
		}
		params.Body = cleanBadWords(params.Body)
		createParams := database.CreateChirpParams{
			Body:   params.Body,
			UserID: id,
		}
		chirp, err := cfg.db.CreateChirp(r.Context(), createParams)
		if err != nil {
			log.Printf("Error: issue creating record for chirp: %s", err)
			w.WriteHeader(400)
			return
		}
		type chirpOutParams struct {
			Body      string    `json:"body"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			ID        uuid.UUID `json:"id"`
			UserID    uuid.UUID `json:"user_id"`
		}
		coParams := chirpOutParams{
			Body:      chirp.Body,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			ID:        chirp.ID,
			UserID:    chirp.UserID,
		}
		data, err := json.Marshal(coParams)
		if err != nil {
			log.Printf("Error: issue marshalling response: %s", err)
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write(data)
	default:
		w.WriteHeader(405)
	}
}

func cleanBadWords(body string) string {
	bWords := []string{"kerfuffle", "sharbert", "fornax"}
	splitBody := strings.Split(body, " ")
	for i, word := range splitBody {
		for _, badWord := range bWords {
			if strings.ToLower(word) == badWord {
				splitBody[i] = "****"
				continue
			}
		}
	}
	return strings.Join(splitBody, " ")
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Printf("Error: Database connection issues: %s", err)
	}

	cfg := new(apiConfig)
	cfg.db = database.New(db)
	cfg.platform = os.Getenv("PLATFORM")
	cfg.secret = os.Getenv("SECRET")

	fServer := http.StripPrefix("/app", http.FileServer(http.Dir(".")))

	sMux := http.NewServeMux()
	sMux.Handle("/app/", cfg.middlewareMetricsInc(fServer))
	sMux.HandleFunc("/app", handlerRedirect)
	sMux.HandleFunc("GET /api/healthz", handlerHealthz)
	sMux.HandleFunc("GET /admin/metrics", cfg.handlerAdmin)
	sMux.HandleFunc("POST /admin/reset", cfg.handlerResetHits)
	sMux.HandleFunc("POST /api/users", cfg.handlerAddUser)
	sMux.HandleFunc("/api/chirps", cfg.handlerChirps)
	sMux.HandleFunc("GET /api/chirps/{chirpID}", cfg.handlerGetChirpByID)
	sMux.HandleFunc("POST /api/login", cfg.handlerLogin)
	sMux.HandleFunc("POST /api/refresh", cfg.handlerRefreshToken)
	sMux.HandleFunc("POST /api/revoke", cfg.handlerRevokeToken)
	server := &http.Server{
		Addr:    ":8080",
		Handler: sMux,
	}
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error: %v", err)
	}
}
