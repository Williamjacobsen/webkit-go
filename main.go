package main

import (
	"context"
	"log"
	"net/http"

	"github.com/Williamjacobsen/webkit-go/env"
	"github.com/Williamjacobsen/webkit-go/oidc"
	"github.com/Williamjacobsen/webkit-go/response"

	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()

	google, err := oidc.New(context.Background(), oidc.ProviderConfig{
		ClientID:             env.GetValue("GOOGLE_CLIENT_ID"),
		ClientSecret:         env.GetValue("GOOGLE_CLIENT_SECRET"),
		RedirectURL:          "http://localhost:8080/login/google/callback",
		IssuerURL:            "https://accounts.google.com",
		Scopes:               []string{"openid", "profile", "email"},
		OnSuccessRedirectURL: "http://localhost:8080/",
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		response.WriteJSON(w, map[string]string{"Page": "Home"})
	})
	mux.HandleFunc("/login/google", google.HandleLogin())
	mux.HandleFunc("/login/google/callback", google.HandleCallback())

	port := ":8080"
	log.Println("Running on port :8080...")
	http.ListenAndServe(port, mux)
}
