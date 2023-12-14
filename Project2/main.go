package main

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/golang-jwt/jwt/v5"
)

var (
	goodPrivKey    *rsa.PrivateKey
	expiredPrivKey *rsa.PrivateKey
	db             *sql.DB
)

func main() {
	setupDatabase()
	genKeys()

	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
	http.HandleFunc("/auth", AuthHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func setupDatabase() {
	var err error
	db, err = sql.Open("sqlite3", "totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys(
			kid INTEGER PRIMARY KEY AUTOINCREMENT,
			key BLOB NOT NULL,
			exp INTEGER NOT NULL
		)
	`)
	if err != nil {
		log.Fatalf("Error creating table: %v", err)
	}
}

func genKeys() {
	var err error
	goodPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA keys: %v", err)
	}

	expiredPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating expired RSA keys: %v", err)
	}

	storeKey(goodPrivKey, time.Now().Add(1*time.Hour).Unix())
	storeKey(expiredPrivKey, time.Now().Add(-1*time.Hour).Unix())
}

func storeKey(privateKey *rsa.PrivateKey, exp int64) {
	keyBytes := serializeKey(privateKey)
	_, err := db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", keyBytes, exp)
	if err != nil {
		log.Fatalf("Error storing key in the database: %v", err)
	}
}

func serializeKey(privateKey *rsa.PrivateKey) []byte {
	return []byte(fmt.Sprintf("%x", privateKey.D.Bytes()))
}

func deserializeKey(data []byte) (*rsa.PrivateKey, error) {
	d := new(big.Int)
	d.SetString(string(data), 16)
	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: goodPrivKey.N,
			E: goodPrivKey.E,
		},
		D: d,
	}, nil
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var (
		signingKey *rsa.PrivateKey
		keyID      string
	)

	if expired, _ := strconv.ParseBool(r.URL.Query().Get("expired")); expired {
		key, exp, kid, err := getKeyFromDatabase(true)
		if err != nil {
			http.Error(w, "failed to get expired key from the database", http.StatusInternalServerError)
			return
		}
		signingKey, _ = deserializeKey(key)
		keyID = strconv.Itoa(kid)

		// Use the expiration time from the database
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"exp": exp,
		})
		token.Header["kid"] = keyID
		signedToken, err := token.SignedString(signingKey)
		if err != nil {
			http.Error(w, "failed to sign token", http.StatusInternalServerError)
			return
		}

		_, _ = w.Write([]byte(signedToken))
	} else {
		key, exp, kid, err := getKeyFromDatabase(false)
		if err != nil {
			http.Error(w, "failed to get non-expired key from the database", http.StatusInternalServerError)
			return
		}
		signingKey, _ = deserializeKey(key)
		keyID = strconv.Itoa(kid)

		// Use the expiration time from the database
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"exp": exp,
		})
		token.Header["kid"] = keyID
		signedToken, err := token.SignedString(signingKey)
		if err != nil {
			http.Error(w, "failed to sign token", http.StatusInternalServerError)
			return
		}

		_, _ = w.Write([]byte(signedToken))
	}
}

func getKeyFromDatabase(isExpired bool) ([]byte, int64, int, error) {
	query := "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1"
	if isExpired {
		query = "SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1"
	}
	row := db.QueryRow(query, time.Now().Unix())
	var keyData []byte
	var kid int
	var exp int64
	err := row.Scan(&kid, &keyData, &exp)
	if err != nil {
		return nil, 0, 0, err
	}
	return keyData, exp, kid, nil
}

type (
	JWKS struct {
		Keys []JWK `json:"keys"`
	}
	JWK struct {
		KID       string `json:"kid"`
		Algorithm string `json:"alg"`
		KeyType   string `json:"kty"`
		Use       string `json:"use"`
		N         string `json:"n"`
		E         string `json:"e"`
	}
)

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	keys, err := getValidKeysFromDatabase()
	if err != nil {
		http.Error(w, "failed to get keys from the database", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(JWKS{Keys: keys})
}

func getValidKeysFromDatabase() ([]JWK, error) {
	rows, err := db.Query("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []JWK
	for rows.Next() {
		var kid int
		var keyData []byte
		err := rows.Scan(&kid, &keyData)
		if err != nil {
			return nil, err
		}

		key, err := deserializeKey(keyData)
		if err != nil {
			return nil, err
		}

		base64URLEncode := func(b *big.Int) string {
			return base64.RawURLEncoding.EncodeToString(b.Bytes())
		}

		publicKey := key.Public().(*rsa.PublicKey)
		keys = append(keys, JWK{
			KID:       strconv.Itoa(kid),
			Algorithm: "RS256",
			KeyType:   "RSA",
			Use:       "sig",
			N:         base64URLEncode(publicKey.N),
			E:         base64URLEncode(big.NewInt(int64(publicKey.E))),
		})
	}
	return keys, nil
}

