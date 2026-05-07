package authkit

import (
	"net/http"
)

type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string // The callback the OIDC service will call with the auth code.
	AuthURL      string // Redirect the user to the OIDC SignIn page e.g. https://accounts.google.com/o/oauth2/auth.
	TokenURL     string // Code for Tokens URL e.g. https://oauth2.googleapis.com/token.
	Scopes       []string
}

func (pc *ProviderConfig) HandleLogin() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
	}
}
