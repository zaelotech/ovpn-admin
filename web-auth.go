package main

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

// webAuthMiddleware provides HTTP Basic Authentication for the web interface
func webAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract Basic Auth credentials
		auth := r.Header.Get("Authorization")
		if auth == "" {
			requestBasicAuth(w, r)
			return
		}

		// Check if it's Basic Auth
		const prefix = "Basic "
		if !strings.HasPrefix(auth, prefix) {
			requestBasicAuth(w, r)
			return
		}

		// Decode base64
		decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
		if err != nil {
			log.Warnf("webAuthMiddleware: base64 decode error from %s: %v", r.RemoteAddr, err)
			requestBasicAuth(w, r)
			return
		}

		// Split username:password
		credentials := strings.SplitN(string(decoded), ":", 2)
		if len(credentials) != 2 {
			log.Warnf("webAuthMiddleware: invalid credentials format from %s", r.RemoteAddr)
			requestBasicAuth(w, r)
			return
		}

		username := credentials[0]
		password := credentials[1]

		// Validate credentials against BoltDB
		if validateWebCredentials(username, password) {
			log.Debugf("webAuthMiddleware: successful authentication for user %s from %s", username, r.RemoteAddr)
			next(w, r)
		} else {
			log.Warnf("webAuthMiddleware: authentication failed for user %s from %s", username, r.RemoteAddr)
			requestBasicAuth(w, r)
		}
	}
}

// requestBasicAuth sends 401 Unauthorized with WWW-Authenticate header
func requestBasicAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Basic realm="OpenVPN Admin"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"status":"error","message":"Authentication required"}`))
}

// validateWebCredentials checks username/password against BoltDB
func validateWebCredentials(username, password string) bool {
	// Open database
	db, err := bbolt.Open(*authDatabase, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Errorf("validateWebCredentials: error opening database: %v", err)
		return false
	}
	defer db.Close()

	var storedHash []byte

	// Read user hash from database
	err = db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("users"))
		if bucket == nil {
			return nil
		}
		storedHash = bucket.Get([]byte(username))
		return nil
	})

	if err != nil {
		log.Errorf("validateWebCredentials: error reading from database: %v", err)
		return false
	}

	// User not found
	if storedHash == nil {
		log.Debugf("validateWebCredentials: user %s not found", username)
		return false
	}

	// Compare password with stored hash using constant-time comparison
	err = bcrypt.CompareHashAndPassword(storedHash, []byte(password))
	if err != nil {
		log.Debugf("validateWebCredentials: password mismatch for user %s", username)
		return false
	}

	return true
}

// wrapWithAuth wraps an http.HandlerFunc with authentication middleware
func wrapWithAuth(handler http.HandlerFunc) http.HandlerFunc {
	if *authByPassword {
		return webAuthMiddleware(handler)
	}
	return handler
}

// wrapHandleWithAuth wraps http.Handle with authentication (for static files)
func wrapHandleWithAuth(pattern string, handler http.Handler) {
	if *authByPassword {
		http.HandleFunc(pattern, webAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
			handler.ServeHTTP(w, r)
		}))
	} else {
		http.Handle(pattern, handler)
	}
}
