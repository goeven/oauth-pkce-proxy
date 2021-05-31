package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

func Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	var (
		challenge       = r.Form.Get("code_challenge")
		challengeMethod = r.Form.Get("code_challenge_method")
		redirectURI     = r.Form.Get("redirect_uri")
		clientState     = r.Form.Get("state")
		scopes          = r.Form["scope"]
	)

	if challenge == "" || challengeMethod != "S256" {
		oauthError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	token, err := ClientClaimsToJWT(challenge, clientState, redirectURI)
	if err != nil {
		log.Printf("Failed to create client claims: %v", err)
		oauthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	authCodeURL := newOAuthConfig(scopes...).AuthCodeURL(token)

	redirect, err := http.NewRequest("GET", authCodeURL, nil)
	if err != nil {
		log.Printf("Failed to create request for redirect: %v", err)
		oauthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, redirect, authCodeURL, http.StatusFound)
}

func Callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	var (
		state                     = r.Form.Get("state")
		upstreamAuthorizationCode = r.Form.Get("code")
	)

	claims, err := ParseClientClaims(state)
	if err != nil {
		log.Printf("Failed to parse client claims from state: %v", err)
		oauthError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	downstreamAuthorizationCode, err := AuthorizationCodeClaimsToJWT(claims.CodeChallenge, upstreamAuthorizationCode)
	if err != nil {
		log.Printf("Failed create authorization code token: %v", err)
		oauthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	redirect, err := http.NewRequest("GET", claims.RedirectURI, nil)
	if err != nil {
		log.Printf("Failed to create request for redirect: %v", err)
		oauthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	u, err := url.Parse(claims.RedirectURI)
	if err != nil {
		log.Printf("Failed to parse redirect URL: %v", err)
		oauthError(w, "server_error", http.StatusInternalServerError)
		return
	}

	query := u.Query()
	query.Add("state", claims.State)
	query.Add("code", downstreamAuthorizationCode)

	u.RawQuery = query.Encode()

	http.Redirect(w, redirect, u.String(), http.StatusFound)
}

func Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	var (
		code         = r.Form.Get("code")
		codeVerifier = r.Form.Get("code_verifier")
	)

	challenge, upstreamCode, err := ParseAuthorizationCodeClaims(code)
	if err != nil {
		log.Printf("Failed to parse jwt from code: %v", err)
		oauthError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	// Verify code challenge.
	sha256sum := sha256.Sum256([]byte(codeVerifier))
	encoded := base64.RawURLEncoding.EncodeToString(sha256sum[:])

	if encoded != challenge {
		log.Printf("Mismatched verifier and code challenge: %v", err)
		oauthError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	oauthToken, err := newOAuthConfig().Exchange(r.Context(), upstreamCode)

	if e, ok := err.(*oauth2.RetrieveError); ok {
		log.Printf("Failed to exchange token: %v", err)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		http.Error(w, string(e.Body), e.Response.StatusCode)
		return
	} else if err != nil {
		log.Printf("Failed to exchange token: %v", err)
		oauthError(w, "unauthorized_client", http.StatusBadRequest)
		return
	}

	oauthResponse(w, oauthToken, http.StatusOK)
}

func newOAuthConfig(scopes ...string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     config.Oauth.ClientID,
		ClientSecret: config.Oauth.ClientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.Oauth.AuthURL,
			TokenURL: config.Oauth.TokenURL,
		},
		RedirectURL: config.Oauth.RedirectURL,
	}
}

func oauthResponse(w http.ResponseWriter, v interface{}, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	body, err := json.Marshal(v)
	if err != nil {
		log.Printf("Failed to json-encode reponse: %v", err)
		oauthResponse(w, "server_error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(code)
	w.Write(body)
}

func oauthError(w http.ResponseWriter, msg string, code int) {
	oauthResponse(w, map[string]string{
		"error": msg,
	}, code)
}
