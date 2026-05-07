package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type User struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

type Claims map[string]any

type ProviderConfig struct {
	ClientID             string
	ClientSecret         string
	RedirectURL          string
	IssuerURL            string
	Scopes               []string
	OnSuccessRedirectURL string
	provider             *gooidc.Provider
	oauth2               *oauth2.Config
}

func New(ctx context.Context, cfg ProviderConfig) (*ProviderConfig, error) {
	provider, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	cfg.provider = provider
	cfg.oauth2 = &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		Endpoint:     provider.Endpoint(),
	}
	return &cfg, nil
}

func (pc *ProviderConfig) HandleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := randomString(16)
		verifier := randomString(32)

		setCookie(w, "state", state)
		setCookie(w, "code_verifier", verifier)

		challenge := codeChallenge(verifier)
		authURL := pc.oauth2.AuthCodeURL(state,
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func (pc *ProviderConfig) HandleCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		stateCookie, _ := r.Cookie("state")
		verifierCookie, _ := r.Cookie("code_verifier")

		if code == "" || state == "" || state != stateCookie.Value || verifierCookie.Value == "" {
			http.Error(w, "Something went wrong during OIDC callback.", http.StatusInternalServerError)
			return
		}

		token, err := pc.oauth2.Exchange(r.Context(), code,
			oauth2.VerifierOption(verifierCookie.Value),
		)
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "Missing id_token in token response", http.StatusInternalServerError)
			return
		}

		verifier := pc.provider.Verifier(&gooidc.Config{ClientID: pc.ClientID})
		idToken, err := verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var claims Claims
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "Failed to parse ID token claims: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Println(claims)
		log.Println(claims.GetString("email"))

		clearCookie(w, "state")
		clearCookie(w, "code_verifier")

		// TODO: Set session cookie.

		http.Redirect(w, r, pc.OnSuccessRedirectURL, http.StatusFound)
	}
}

func (c Claims) GetString(key string) (string, error) {
	if value, ok := c[key]; ok {
		if _string, ok := value.(string); ok {
			return _string, nil
		}
	}
	return "", fmt.Errorf("Could not get key '%s' from claims.", key)
}

func (c Claims) GetBool(key string) (bool, error) {
	if value, ok := c[key]; ok {
		if _bool, ok := value.(bool); ok {
			return _bool, nil
		}
	}
	return false, fmt.Errorf("Could not get key '&s' from claims.", key)
}

func randomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func codeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func setCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Path: "/",
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
}
