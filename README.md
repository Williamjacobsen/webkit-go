# webkit-go

Minimal OpenID Connect (OIDC) authentication with PKCE for Go `net/http`.

## Packages

| Package | Path | Purpose |
|---------|------|---------|
| `oidc` | `github.com/Williamjacobsen/webkit-go/oidc` | OIDC PKCE authorization code flow |
| `response` | `github.com/Williamjacobsen/webkit-go/response` | JSON response helpers |
| `env` | `github.com/Williamjacobsen/webkit-go/env` | Environment variable loading |

## Installation

```bash
go get github.com/Williamjacobsen/webkit-go
```

## Quick Start

```go
package main

import (
	"log"
	"net/http"

	"github.com/Williamjacobsen/webkit-go/env"
	"github.com/Williamjacobsen/webkit-go/oidc"
	"github.com/Williamjacobsen/webkit-go/response"

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

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		response.WriteJSON(w, map[string]string{"Page": "Home"})
	})
	mux.HandleFunc("/login/google", google.HandleLogin())

	port := ":8080"
	log.Println("Running on port :8080...")
	http.ListenAndServe(port, mux)
}
```

## How PKCE works

PKCE (Proof Key for Code Exchange, RFC 7636) protects against authorization code interception.

1. `HandleLogin()` generates a random `code_verifier` and its SHA-256 hash (`code_challenge`)
2. The `code_verifier` is stored in an `HttpOnly` cookie
3. The user is redirected to the provider with the `code_challenge` as a query parameter
4. On callback, the `code_verifier` is sent along with the authorization code to the token endpoint
5. The provider verifies `SHA-256(code_verifier) == code_challenge` before issuing tokens

An attacker who intercepts the authorization code cannot exchange it for tokens without the `code_verifier`.

## OIDC package

Package `oidc` implements the OIDC authorization code flow with PKCE.

### ProviderConfig

```go
type ProviderConfig struct {
	ClientID     string   // OIDC client ID
	ClientSecret string   // OIDC client secret
	RedirectURL  string   // Callback URL registered with the provider
	AuthURL      string   // Provider's authorization endpoint
	TokenURL     string   // Provider's token endpoint
	Scopes       []string // e.g. openid, profile, email
}
```

### HandleLogin() http.HandlerFunc

Initiates the OIDC login flow. Generates PKCE verifier and challenge, stores state and verifier in HttpOnly cookies, and redirects the user to the provider's authorization endpoint.

## Response package

```go
func WriteJSON(writer http.ResponseWriter, message any)
```

Sets `Content-Type: application/json` and encodes the value as JSON. Returns HTTP 500 on encoding failure.

## Env package

```go
func GetValue(key string) string
```

Reads an environment variable. Logs and exits with code 1 if the variable is empty or unset.

## Supported Providers

Any provider that supports the OIDC authorization code flow with PKCE:

- Google
- Auth0
- Okta
- Azure AD / Entra ID
- Keycloak

## License

MIT
