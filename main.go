package main

import (
	"context"
	"log"
	"net/http"

	"github.com/Williamjacobsen/webkit-go/env"
	"github.com/Williamjacobsen/webkit-go/oidc"
	"github.com/Williamjacobsen/webkit-go/response"
	"github.com/Williamjacobsen/webkit-go/store"

	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()

	db := &store.Store{
		Path: "./test.db",
	}
	db.Init_db()
	defer db.Close()
	// init_db_tables(db)

	google, err := oidc.New(context.Background(), oidc.ProviderConfig{
		ClientID:             env.GetValue("GOOGLE_CLIENT_ID"),
		ClientSecret:         env.GetValue("GOOGLE_CLIENT_SECRET"),
		RedirectURL:          "http://localhost:8080/login/google/callback",
		IssuerURL:            "https://accounts.google.com",
		Scopes:               []string{"openid", "profile", "email"},
		OnSuccessRedirectURL: "http://localhost:8080/",
		CallbackFunc: func(claims oidc.Claims) {
			// store_user(db, claims)
		},
		DB: db,
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

func init_db_tables(db *store.Store) {
	db.DB.Exec(`CREATE TABLE IF NOT EXISTS users (
		sub TEXT PRIMARY KEY,
		email TEXT,
		name TEXT,
		picture TEXT
	)`)
}

func store_user(db *store.Store, claims oidc.Claims) {
	sub, _ := claims.GetString("sub")
	email, _ := claims.GetString("email")
	name, _ := claims.GetString("name")
	picture, _ := claims.GetString("picture")
	_, err := db.DB.Exec(
		`INSERT INTO users (sub, email, name, picture) VALUES (?, ?, ?, ?)
		 ON CONFLICT(sub) DO UPDATE SET email=excluded.email, name=excluded.name, picture=excluded.picture`,
		sub, email, name, picture,
	)
	if err != nil {
		log.Printf("Failed to store user: %v", err)
	}
}
