package main

import (
	"log"
	"net/http"

	env "github.com/Williamjacobsen/webkit-go/env"
	oidc "github.com/Williamjacobsen/webkit-go/oidc"

	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()

	mux := http.NewServeMux()

	google := oidc.ProviderConfig{
		ClientID:     env.GetValue("GOOGLE_CLIENT_ID"),
		ClientSecret: env.GetValue("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/callback",
		AuthURL:      "https://accounts.google.com/o/oauth2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		Scopes:       []string{"openid", "profile", "email"},
	}

	mux.HandleFunc("/", google.HandleLogin())

	port := ":8080"
	log.Println("Runnning on port :8080...")
	http.ListenAndServe(port, mux)
}
