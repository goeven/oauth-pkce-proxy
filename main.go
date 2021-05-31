package main

import (
	"fmt"
	"log"
	"net/http"
)

// Flow:
//
// 1. /oauth/authorize -> encrypt code_challenge in the state param -> redirect to upstream oauth url -> user logins -> upstream redirects to "/callback" w/ upstream authz code & state
// 2. /callback -> encrypt upstream authz code in own authz code -> redirects to deep link -> app sends authz code + code_verifier to /oauth/token
// 3. /oauth/token -> decrypt authz code to get code_challenge and verify it with code_verifier -> use upstream authz to get token return it
//
func main() {
	http.Handle("/oauth/authorize", http.HandlerFunc(Authorize))
	http.Handle("/callback", http.HandlerFunc(Callback))
	http.Handle("/oauth/token", http.HandlerFunc(Token))

	addr := fmt.Sprintf(":%d", config.Port)

	log.Printf("Listening on %s", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Failed to start http server: %v", err)
	}
}
