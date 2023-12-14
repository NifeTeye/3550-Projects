package main

import (
	"bytes" // Add this line to import the "bytes" package
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const keyEnvVar = "NOT_MY_KEY"

var (
	goodPrivKey    *rsa.PrivateKey
	expiredPrivKey *rsa.PrivateKey
	db             *sql.DB
	limiter        = NewRateLimiter(1, time.Second)
)

func main() {
	setupDatabase()
	genKeys()

	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
	http.HandleFunc("/auth", AuthHandler)
	http.HandleFunc("/register", RegisterHandler)

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

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			email TEXT UNIQUE,
			date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_login TIMESTAMP
		)
	`)
	if err != nil {
		log.Fatalf("Error creating users table: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS auth_logs(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_ip TEXT NOT NULL,
			request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			user_id INTEGER,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		log.Fatalf("Error creating auth_logs table: %v", err)
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

	storeEncryptedKey(goodPrivKey, time.Now().Add(1*time.Hour).Unix())
	storeEncryptedKey(expiredPrivKey, time.Now().Add(-1*time.Hour).Unix())
}


func getEncryptionKey() []byte {
	key := os.Getenv(keyEnvVar)
	if key == "" {
		log.Fatalf("Encryption key not found in environment variable %s", keyEnvVar)
	}

	keyBytes := []byte(key)
	log.Printf("Key length: %d, Key content: %v", len(keyBytes), keyBytes)

	// Check if the key length is valid
	if len(keyBytes) != 16 {
		log.Printf("Invalid key size. The key must be 16 bytes. Truncating or padding the key.")

		// If the key is longer than 16 bytes, truncate it
		if len(keyBytes) > 16 {
			keyBytes = keyBytes[:16]
		}

		// If the key is shorter than 16 bytes, pad it with zeros
		for len(keyBytes) < 16 {
			keyBytes = append(keyBytes, 0)
		}
	}

	return keyBytes
}

func encrypt(data []byte) ([]byte, error) {
	key := getEncryptionKey()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Pad the data to a multiple of the block size
	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	paddedData := append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)

	// Use a random IV for each encryption
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedData))
	mode.CryptBlocks(ciphertext, paddedData)

	// Prepend the IV to the ciphertext
	ciphertext = append(iv, ciphertext...)

	return ciphertext, nil
}

func decrypt(data []byte) ([]byte, error) {
	key := getEncryptionKey()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	return data, nil
}

func storeEncryptedKey(privateKey *rsa.PrivateKey, exp int64) {
	keyBytes := serializeKey(privateKey)
	encryptedKey, err := encrypt(keyBytes)
	if err != nil {
		log.Fatalf("Error encrypting key: %v", err)
	}

	if encryptedKey == nil {
		log.Fatal("Encrypted key is nil")
	}

	_, err = db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", encryptedKey, exp)
	if err != nil {
		log.Fatalf("Error storing key in the database: %v", err)
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

	decryptedKey, err := decrypt(keyData)
	if err != nil {
		return nil, 0, 0, err
	}

	return decryptedKey, exp, kid, nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func generateUUID() string {
	uuid := uuid.New()
	return uuid.String()
}


func registerUser(username, email string) (string, error) {
	password := generateUUID() // Implement this function to generate UUIDv4
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return "", err
	}

	_, err = db.Exec("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", username, hashedPassword, email)
	if err != nil {
		return "", err
	}

	return password, nil
}

func logAuthRequest(requestIP string, userID int) {
	_, err := db.Exec("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", requestIP, userID)
	if err != nil {
		log.Printf("Error logging authentication request: %v", err)
	}
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

		decryptedKey, err := decrypt(keyData)
		if err != nil {
			return nil, err
		}

		key, err := deserializeKey(decryptedKey)
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

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if !limiter.Allow() {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
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

	// Get user ID from authentication logic (replace with actual logic)
	userID := 123

	// Log the authentication request
	logAuthRequest(r.RemoteAddr, userID)
}

// Add this section

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
   if r.Method != http.MethodPost {
      w.WriteHeader(http.StatusMethodNotAllowed)
      return
   }

   var registrationRequest struct {
      Username string `json:"username"`
      Email    string `json:"email"`
   }

   decoder := json.NewDecoder(r.Body)
   if err := decoder.Decode(&registrationRequest); err != nil {
      http.Error(w, "failed to decode registration request", http.StatusBadRequest)
      return
   }

   // Generate a secure password using UUIDv4
   password := generateUUID()

   // Hash the password using Argon2
   hashedPassword, err := hashPassword(password)
   if err != nil {
      http.Error(w, "failed to hash password", http.StatusInternalServerError)
      return
   }

   // Store user details and hashed password in the database
   err = storeUser(registrationRequest.Username, hashedPassword, registrationRequest.Email)
   if err != nil {
      http.Error(w, "failed to store user details", http.StatusInternalServerError)
      return
   }

   // Return the generated password to the user
      response := map[string]string{"password": password}
   jsonResponse, err := json.Marshal(response)
   if err != nil {
      http.Error(w, "failed to encode response", http.StatusInternalServerError)
      return
   }

   w.Header().Set("Content-Type", "application/json")
   w.WriteHeader(http.StatusOK)
   _, _ = w.Write(jsonResponse)
}

func serializeKey(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}

func deserializeKey(data []byte) (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS1PrivateKey(data)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func storeUser(username, passwordHash, email string) error {
	_, err := db.Exec("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", username, passwordHash, email)
	return err
}

type RateLimiter struct {
	tokens     int
	lastUpdate time.Time
	interval   time.Duration
}

// NewRateLimiter creates a new RateLimiter instance.
func NewRateLimiter(tokens int, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		tokens:     tokens,
		lastUpdate: time.Now(),
		interval:   interval,
	}
}

// Allow checks if a request is allowed based on the rate limit.
func (r *RateLimiter) Allow() bool {
	currentTime := time.Now()
	elapsed := currentTime.Sub(r.lastUpdate)

	if elapsed >= r.interval {
		r.tokens = 1
		r.lastUpdate = currentTime
		return true
	}

	if r.tokens > 0 {
		r.tokens--
		return true
	}

	return false
}


