package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Williamjacobsen/authkit-go/authkit"
	"github.com/joho/godotenv"
)

var auth *authkit.Auth

func main() {
	godotenv.Load()

	auth = authkit.New(authkit.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/callback",
		Issuer:       "https://accounts.google.com",
		Scopes:       []string{"openid", "profile", "email"},
		CallbackFunc: PostProcessOAuth,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/login", auth.LoginHandler())
	mux.HandleFunc("/callback", auth.CallbackHandler())
	mux.HandleFunc("/logout", auth.LogoutHandler())

	addr := ":8080"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleHome(writer http.ResponseWriter, request *http.Request) {
	user, err := auth.UserFromRequest(request)
	if err != nil {
		fmt.Fprint(writer, `<h1>Home</h1><a href="/login">Login with Google</a>`)
		return
	}

	fmt.Fprintf(writer, `<h1>Welcome, %s</h1>
<p>Email: %s</p>
<br><a href="/logout">Logout</a>`, user.GetString("name"), user.GetString("email"))
}

func PostProcessOAuth(user *authkit.User, writer http.ResponseWriter, request *http.Request) {
	log.Println(user)

	email := user.GetString("email")
	log.Println("email:", email)

	writeJSON(writer, user)
}

func writeJSON(writer http.ResponseWriter, message any) {
	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(message)
}
