package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/evakv0th/goserver/internal/auth"
	"github.com/evakv0th/goserver/internal/database"
	"github.com/evakv0th/goserver/internal/handlers"
	"github.com/evakv0th/goserver/internal/middlewares"
	"github.com/evakv0th/goserver/internal/utils"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func main() {
	godotenv.Load()
	dbURL := utils.GetEnvVariable("DB_URL")
	platform := utils.GetEnvVariable("PLATFORM")
	jwtSecret := utils.GetEnvVariable("JWT_SECRET")
	polkaKey := utils.GetEnvVariable("POLKA_KEY")

	dbConn, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error opening database: %s", err)
	}
	dbQueries := database.New(dbConn)

	const filepathRoot = "."
	const port = "8080"
	apiCfg := apiConfig{
		fileserverHits: atomic.Int32{},
		db:             dbQueries,
		platform:       platform,
		jwtSecret:      jwtSecret,
		polkaKey:       polkaKey,
	}

	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))
	mux.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("./assets"))))

	mux.HandleFunc("GET /api/healthz", handlers.HandlerReadiness)
	mux.HandleFunc("POST /api/login", apiCfg.handlerLogin)
	mux.HandleFunc("POST /api/users", apiCfg.handlerUsersCreate)
	mux.HandleFunc("PUT /api/users", apiCfg.handlerUpdateUsers)
	mux.HandleFunc("GET /api/chirps", apiCfg.handlerGetAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handlerGetOneChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handlerDeleteChirp)
	mux.HandleFunc("POST /api/chirps", apiCfg.handlerValidateChirp)
	mux.HandleFunc("POST /api/refresh", apiCfg.handlerRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handlerRevoke)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handlerUpgradeChirpyRedWebhook)

	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerGetMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.handlerResetMetrics)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: middlewares.MiddlewareLog(mux),
	}

	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(srv.ListenAndServe())
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerGetMetrics(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) handlerResetMetrics(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Forbidden"))
	}
	cfg.fileserverHits.Store(0)
	cfg.db.DeleteUsers(r.Context())
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0"))
}

func (cfg *apiConfig) handlerUsersCreate(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type response struct {
		User
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't decode parameters: %s", err))
		return
	}
	hashedPw, err := auth.HashPassword(params.Password)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't hash password: %s", err))
		return
	}

	user, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPw,
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't create user: %s", err))
		return
	}

	utils.RespondWithJSON(w, http.StatusCreated, response{
		User: User{
			ID:          user.ID,
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
			Email:       user.Email,
			IsChirpyRed: user.IsChirpyRed,
		},
	})
}

func (cfg *apiConfig) handlerUpdateUsers(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type response struct {
		User
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't decode parameters: %s", err))
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, fmt.Sprintf("Couldnt get token: %s", err))
		return
	}

	userUuid, err := auth.ValidateJWT(token, cfg.jwtSecret)

	if userUuid == uuid.Nil || err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	hashedPw, err := auth.HashPassword(params.Password)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't hash password: %s", err))
		return
	}

	user, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userUuid,
		Email:          params.Email,
		HashedPassword: hashedPw,
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't update user: %s", err))
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response{
		User: User{
			ID:          user.ID,
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
			Email:       user.Email,
			IsChirpyRed: user.IsChirpyRed,
		},
	})
}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type response struct {
		User
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)

	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't decode parameters: %s", err))
		return
	}

	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't hash password: %s", err))
		return
	}
	user, err := cfg.db.GetUser(r.Context(), params.Email)

	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	isHashedMatch, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil || !isHashedMatch {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Making jwt failed")
		return
	}
	refreshToken := auth.MakeRefreshToken()

	_, err = cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().UTC().Add(time.Hour * 24 * 60),
	})

	utils.RespondWithJSON(w, http.StatusOK, response{
		User: User{
			ID:           user.ID,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			Email:        user.Email,
			Token:        token,
			RefreshToken: refreshToken,
			IsChirpyRed:  user.IsChirpyRed,
		},
	})
}

func (cfg *apiConfig) handlerValidateChirp(w http.ResponseWriter, r *http.Request) {

	type parameters struct {
		Body   string    `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}
	type response struct {
		Chirp
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't decode parameters: %s", err))
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldnt get token: %s", err))
		return
	}

	userUuid, err := auth.ValidateJWT(token, cfg.jwtSecret)

	if userUuid == uuid.Nil || err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if len([]rune(params.Body)) >= 140 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Chirp is too long"))
		return
	}
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	words := strings.Split(params.Body, " ")
	badWords := []string{"kerfuffle", "sharbert", "fornax"}
	for i, v := range words {
		if slices.Contains(badWords, strings.ToLower(v)) {
			words[i] = "****"
		}
	}
	params.Body = strings.Join(words, " ")

	chirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{Body: params.Body, UserID: userUuid})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't create user: %s", err))
		return
	}
	utils.RespondWithJSON(w, http.StatusCreated, response{
		Chirp: Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		},
	})
}

func (cfg *apiConfig) handlerGetAllChirps(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("author_id")

	sortDirection := "asc"
	sortDirectionParam := r.URL.Query().Get("sort")
	if sortDirectionParam == "desc" {
		sortDirection = "desc"
	}

	var chirpsDB []database.Chirp
	var err error

	if userId != "" {
		chirpsDB, err = cfg.db.GetChirpsWithAuthorId(r.Context(), uuid.MustParse(userId))
	} else {
		chirpsDB, err = cfg.db.GetChirps(r.Context())
	}

	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't get chirps: %s", err))
		return
	}

	chirps := make([]Chirp, len(chirpsDB))
	for i, c := range chirpsDB {
		chirps[i] = Chirp{
			ID:        c.ID,
			CreatedAt: c.CreatedAt,
			UpdatedAt: c.UpdatedAt,
			Body:      c.Body,
			UserID:    c.UserID,
		}
	}

	sort.Slice(chirps, func(i, j int) bool {
		if sortDirection == "desc" {
			return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
		}
		return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
	})

	utils.RespondWithJSON(w, http.StatusOK, chirps)
}

func (cfg *apiConfig) handlerGetOneChirp(w http.ResponseWriter, r *http.Request) {
	chirpIDStr := r.PathValue("chirpID")
	if chirpIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Missing chirp ID in path")
		return
	}

	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}

	chirp, err := cfg.db.GetChirp(r.Context(), chirpID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.RespondWithError(w, http.StatusNotFound, "Chirp not found")
			return
		}
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't get chirp: %s", err))
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	})
}
func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	chirpIDStr := r.PathValue("chirpID")
	if chirpIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Missing chirp ID in path")
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, fmt.Sprintf("Couldnt get token: %s", err))
		return
	}

	userUuid, err := auth.ValidateJWT(token, cfg.jwtSecret)

	if userUuid == uuid.Nil || err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}

	chirp, err := cfg.db.GetChirp(r.Context(), chirpID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.RespondWithError(w, http.StatusNotFound, "Chirp not found")
			return
		}
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't get chirp: %s", err))
		return
	}

	if chirp.UserID != userUuid {
		utils.RespondWithError(w, http.StatusForbidden, "Forbiden")
		return
	}

	err = cfg.db.DeleteChirp(r.Context(), chirpID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "couldnt delete chirp")
		return
	}
	utils.RespondWithJSON(w, http.StatusNoContent, struct{}{})
}

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Token string `json:"token"`
	}

	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("Couldn't find token: %s", err))
		return
	}

	user, err := cfg.db.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, fmt.Sprintf("Couldn't get user for refresh token: %s", err))
		return
	}

	accessToken, err := auth.MakeJWT(
		user.ID,
		cfg.jwtSecret,
		time.Hour,
	)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, fmt.Sprintf("Couldn't validate token: %s", err))
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response{
		Token: accessToken,
	})
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("Couldn't find token: %s", err))
		return
	}

	_, err = cfg.db.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't revoke session: %s", err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handlerUpgradeChirpyRedWebhook(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserId uuid.UUID `json:"user_id"`
		} `json:"data"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't decode parameters: %s", err))
		return
	}
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil || apiKey != cfg.polkaKey {
		utils.RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if params.Event != "user.upgraded" {
		utils.RespondWithJSON(w, http.StatusNoContent, struct{}{})
		return
	}

	_, err = cfg.db.UpgradeUserChirpyRed(r.Context(), params.Data.UserId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.RespondWithError(w, http.StatusNotFound, "User not found")
			return
		}
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't upgrade user: %s", err))
		return
	}

	utils.RespondWithJSON(w, http.StatusNoContent, struct{}{})
}
