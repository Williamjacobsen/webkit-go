package main

import (
	"log"
	"net/http"
	"os"

	"github.com/Williamjacobsen/authkit-go/authkit"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()

	auth := authkit.New(authkit.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/callback",
		Issuer:       "https://accounts.google.com",
		Scopes:       []string{"openid", "profile", "email"},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/login", auth.LoginHandler())
	mux.HandleFunc("/callback", auth.CallbackHandler())

	addr := ":8080"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
