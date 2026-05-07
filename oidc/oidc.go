// Package oidc implements the OpenID Connect (OIDC) authorization code flow
// with PKCE (Proof Key for Code Exchange) for secure authentication.
//
// PKCE protects against authorization code interception by binding the
// authorization code to the client session via a code_verifier stored in
// an HttpOnly cookie. The code_challenge (SHA-256 hash of verifier) is
// sent in the initial auth request, and the raw verifier is required
// at the token exchange endpoint.

package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
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
		state := generateRandomString(16)
		verifier := generateRandomString(32)
		challenge := generateCodeChallenge(verifier)

		http.SetCookie(writer, &http.Cookie{
			Name:     "state",
			Value:    state,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		})
		http.SetCookie(writer, &http.Cookie{
			Name:     "code_verifier",
			Value:    verifier,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		})

		authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
			pc.AuthURL,
			pc.ClientID,
			pc.RedirectURL,
			strings.Join(pc.Scopes, " "),
			state,
			challenge,
		)
		http.Redirect(writer, request, authURL, http.StatusFound)
	}
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
