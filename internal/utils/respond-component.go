package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

func RespondWithError(w http.ResponseWriter, code int, msg string) {
	log.Printf("%s", msg)
	w.WriteHeader(code)
}

func RespondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	data, err := json.Marshal(payload)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Error marshalling JSON: %s", err))
		return
	}

	w.Write(data)
}

func GetEnvVariable(variable string) string {
	v := os.Getenv(variable)
	if v == "" {
		log.Fatal(fmt.Sprintf("%s must be set", variable))
	}
	return v
}
