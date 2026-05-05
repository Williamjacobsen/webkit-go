# Authkit-go

**Opinionated OpenID Connect (OIDC) authentication toolkit for Go APIs, with sessions, middleware, and clean net/http integration.**

---

## Why Authkit-go?

Adding OIDC authentication in Go usually means wiring together:

- net/http
- go-oidc
- golang.org/x/oauth2

…plus handling state, nonce, token verification, cookies, and middleware.

`Authkit-go` gives you a **minimal, opinionated layer** on top of that:

- 🔐 OIDC login flow (login + callback)
- 🍪 Secure session cookies (signed)
- 🧩 Middleware for protected routes
- 👤 Simple user access via context
- ⚙️ Built on standard `net/http`

No frameworks. No magic. Just less boilerplate.

---

## Features

- OpenID Connect (OIDC) authentication
- Secure cookie-based sessions
- `RequireAuth` and `OptionalAuth` middleware
- Context-based user access
- Sensible security defaults (state, nonce, cookie flags)
- Works with any OIDC provider

---

## Installation

```bash
go get github.com/Williamjacobsen/authkit-go
```

---

## Quick Start

```go
package main

import (
    "encoding/json"
    "net/http"

    "github.com/Williamjacobsen/authkit-go"
)

func main() {
    auth := authkit.New(authkit.Config{
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        RedirectURL:  "http://localhost:8080/callback",
        CookieSecret: []byte("super-secret-key"),
    })

    mux := http.NewServeMux()

    mux.Handle("/login", auth.LoginHandler())
    mux.Handle("/callback", auth.CallbackHandler())
    mux.Handle("/logout", auth.LogoutHandler())

    mux.Handle("/me",
        auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user, _ := authkit.UserFromContext(r.Context())
            json.NewEncoder(w).Encode(user)
        })),
    )

    http.ListenAndServe(":8080", mux)
}
```

---

## Middleware

### RequireAuth

Protect routes that require authentication:

```go
mux.Handle("/private", auth.RequireAuth(handler))
```

- Redirects to `/login` if unauthenticated
- Injects user into context if authenticated

---

### OptionalAuth

Allows both anonymous and authenticated users:

```go
mux.Handle("/public", auth.OptionalAuth(handler))
```

---

## Accessing the User

```go
user, ok := authkit.UserFromContext(r.Context())
if !ok {
    // not authenticated
}
```

### User structure

```go
type User struct {
    Subject string
    Email   string
    Name    string
    Picture string
}
```

---

## Session Management

- Cookie-based sessions (signed)
- No database required
- Automatic expiry handling

Built using secure cookie practices via gorilla/securecookie.

---

## Security

`Authkit-go` includes the essential protections required for OIDC:

- ✅ State validation (CSRF protection)
- ✅ Nonce validation (replay protection)
- ✅ ID token verification
- ✅ Secure cookies (HttpOnly, SameSite, Secure)

You are still responsible for:

- Using HTTPS in production
- Keeping secrets safe
- Configuring your OIDC provider correctly

---

## Configuration

```go
type Config struct {
    ClientID     string
    ClientSecret string
    RedirectURL  string

    Scopes []string // defaults to: openid, profile, email

    CookieSecret []byte
    CookieName   string
}
```

---

## Supported Providers

Any provider that implements OpenID Connect should work.

Examples include:

- Google
- Auth0
- Okta
- Azure AD

---

## Design Philosophy

- Minimal surface area
- Explicit over magic
- Secure by default
- Easy to drop down to raw `net/http`

---

## Roadmap

- [ ] Multiple provider support helpers
- [ ] Redis-backed sessions
- [ ] JWT (stateless) mode
- [ ] Role / claim-based middleware
- [ ] CLI scaffolding

---

## Contributing

Contributions are welcome. Open an issue or submit a PR.

---

## License

MIT
