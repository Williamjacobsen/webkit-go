package authkit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type User struct {
	Subject string
	Claims  map[string]any
}

func (u *User) GetString(key string) string {
	value, _ := u.Claims[key].(string)
	return value
}

func (u *User) GetBool(key string) bool {
	value, _ := u.Claims[key].(bool)
	return value
}

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Issuer       string
	CallbackFunc func(user *User, writer http.ResponseWriter, request *http.Request)
	Store        SessionStore
	DBPath       string
	CookieName   string
	MaxAge       int
}

type Auth struct {
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	callbackFunc func(user *User, writer http.ResponseWriter, request *http.Request)
	store        SessionStore
	cookieName   string
	maxAge       int
}

func New(config Config) *Auth {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		panic("failed to discover OIDC provider: " + err.Error())
	}

	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID}
	}

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	store := config.Store
	if store == nil {
		dbPath := config.DBPath
		if dbPath == "" {
			dbPath = "authkit.db"
		}
		sqliteStore, err := NewSQLiteStore(dbPath)
		if err != nil {
			panic("failed to create SQLite store: " + err.Error())
		}
		store = sqliteStore
	}

	cookieName := config.CookieName
	if cookieName == "" {
		cookieName = "authkit_session"
	}

	maxAge := config.MaxAge
	if maxAge == 0 {
		maxAge = 86400
	}

	return &Auth{
		oauth2Config: oauth2Config,
		verifier:     verifier,
		callbackFunc: config.CallbackFunc,
		store:        store,
		cookieName:   cookieName,
		maxAge:       maxAge,
	}
}

func (a *Auth) LoginHandler() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		state := generateRandomState()
		http.Redirect(writer, request, a.oauth2Config.AuthCodeURL(state), http.StatusFound)
	}
}

func (a *Auth) CallbackHandler() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if errorMessage := request.URL.Query().Get("error"); errorMessage != "" {
			http.Error(writer, errorMessage, http.StatusBadRequest)
			return
		}

		code := request.URL.Query().Get("code")
		if code == "" {
			http.Error(writer, "missing code", http.StatusBadRequest)
			return
		}

		ctx := request.Context()
		token, err := a.oauth2Config.Exchange(ctx, code)
		if err != nil {
			http.Error(writer, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(writer, "missing id_token", http.StatusInternalServerError)
			return
		}

		idToken, err := a.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(writer, "id token verification failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var claims map[string]any
		if err := idToken.Claims(&claims); err != nil {
			http.Error(writer, "failed to parse claims: "+err.Error(), http.StatusInternalServerError)
			return
		}

		user := User{
			Subject: idToken.Subject,
			Claims:  claims,
		}

		sessionID := generateSessionID()
		if err := a.store.Save(sessionID, &user, a.maxAge); err != nil {
			http.Error(writer, "failed to save session: "+err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(writer, &http.Cookie{
			Name:     a.cookieName,
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   a.maxAge,
		})

		if a.callbackFunc != nil {
			a.callbackFunc(&user, writer, request)
		} else {
			writer.Header().Set("Content-Type", "application/json")
			json.NewEncoder(writer).Encode(user)
		}
	}
}

func (a *Auth) LogoutHandler() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie(a.cookieName)
		if err == nil {
			a.store.Delete(cookie.Value)
		}

		http.SetCookie(writer, &http.Cookie{
			Name:     a.cookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})

		http.Redirect(writer, request, "/", http.StatusFound)
	}
}

func (a *Auth) UserFromRequest(request *http.Request) (*User, error) {
	cookie, err := request.Cookie(a.cookieName)
	if err != nil {
		return nil, err
	}

	return a.store.Load(cookie.Value)
}

func generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateRandomState() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
