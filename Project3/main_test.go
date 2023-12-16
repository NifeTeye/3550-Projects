package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"errors"
)

func TestEncryptDecrypt(t *testing.T) {
	plaintext := []byte("test message")

	ciphertext, err := encrypt(plaintext)
	require.NoError(t, err, "Error encrypting message")

	decrypted, err := decrypt(ciphertext)
	require.NoError(t, err, "Error decrypting message")

	require.Equal(t, plaintext, decrypted, "Decrypted message does not match plaintext")
}

func TestStoreEncryptedKey(t *testing.T) {
	setupDatabase()
	genKeys()

	storeEncryptedKey(goodPrivKey, time.Now().Add(1*time.Hour).Unix())
	encryptedKey, exp, kid, err := getKeyFromDatabase(false)
	require.NoError(t, err, "Error fetching key from the database")
	decryptedKey, err := decrypt(encryptedKey)
	require.NoError(t, err, "Error decrypting key")

	originalKey, _ := serializeKey(goodPrivKey)
	require.Equal(t, originalKey, decryptedKey, "Decrypted key does not match the original key")
	require.Greater(t, exp, time.Now().Unix(), "Key has expired")
	require.Greater(t, kid, 0, "Invalid kid")
}

func TestGetValidKeysFromDatabase(t *testing.T) {
	setupDatabase()
	genKeys()
	keys, err := getValidKeysFromDatabase()
	require.NoError(t, err, "Error fetching valid keys from the database")

	// Check if the keys are valid
	for _, key := range keys {
		// Decrypt the key and check if it's valid
		decryptedKey, err := decrypt([]byte(key.N))
		require.NoError(t, err, "Error decrypting key")

		_, err = deserializeKey(decryptedKey)
		require.NoError(t, err, "Error deserializing key")
	}
}

func TestAuthHandler(t *testing.T) {
	setupDatabase()
	genKeys()

	// Create a mock HTTP request for testing
	req, err := http.NewRequest("POST", "/auth", nil)
	require.NoError(t, err, "Error creating request")

	rr := httptest.NewRecorder()

	mockDatabase := &MockDatabase{}
	mockDatabase.On("getKeyFromDatabase", false).Return([]byte("mockedKey"), time.Now().Add(1*time.Hour).Unix(), 1, nil)
	db = mockDatabase
	AuthHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "Unexpected status code")

	// Assert the response body (you may need to adapt this based on your actual implementation)
	require.Contains(t, rr.Body.String(), "mockedToken", "Response body does not contain expected token")
	mockDatabase.AssertExpectations(t)
}

func TestRegisterHandler(t *testing.T) {
	setupDatabase()

	req, err := http.NewRequest("POST", "/register", nil)
	require.NoError(t, err, "Error creating request")
	rr := httptest.NewRecorder()

	// Mock the storeUser database call
	mockDatabase := &MockDatabase{}
	mockDatabase.On("storeUser", "testuser", mock.AnythingOfType("string"), "test@example.com").Return(nil)
	db = mockDatabase
	registrationRequest := `{"username": "testuser", "email": "test@example.com"}`
	req.Body = ioutil.NopCloser(bytes.NewBufferString(registrationRequest))
	RegisterHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "Unexpected status code")

	mockDatabase.AssertExpectations(t)
}

func TestJWKSHandler(t *testing.T) {
	setupDatabase()
	genKeys()

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	JWKSHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "Unexpected status code")

	var jwks JWKS
	err = json.Unmarshal(rr.Body.Bytes(), &jwks)
	require.NoError(t, err, "Error unmarshalling JWKS response")
	require.Greater(t, len(jwks.Keys), 0, "Unexpected number of keys in JWKS")
}

func TestRateLimiter(t *testing.T) {
	rateLimiter := NewRateLimiter(2, 1*time.Second, 2)
	require.True(t, rateLimiter.Allow(), "First request should be allowed")
	require.True(t, rateLimiter.Allow(), "Second request should be allowed")
	require.False(t, rateLimiter.Allow(), "Third request should not be allowed")
	time.Sleep(2 * time.Second)

	require.True(t, rateLimiter.Allow(), "Fourth request should be allowed")
}
type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) getKeyFromDatabase(isExpired bool) ([]byte, int64, int, error) {
	args := m.Called(isExpired)
	return args.Get(0).([]byte), args.Get(1).(int64), args.Get(2).(int), args.Error(3)
}

func (m *MockDatabase) storeUser(username, passwordHash, email string) error {
	args := m.Called(username, passwordHash, email)
	return args.Error(0)
}

var (
	ErrTest = errors.New("test error")
)

var err = ErrTest
