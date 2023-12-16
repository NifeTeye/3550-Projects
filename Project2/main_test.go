package main

import (
	"os"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	setupDatabase()
	genKeys()

	// Run tests only if the database is properly set up
	if db != nil {
		exitCode := m.Run()

		// Exit with the code from the tests
		os.Exit(exitCode)
	} else {
		fmt.Println("Error setting up the database. Tests skipped.")
	}
}

func TestSetupDatabase(t *testing.T) {
	// Test checking for errors in sql.Open
	t.Run("CheckOpenErrors", func(t *testing.T) {
		// Create a temporary SQLite file for testing
		tempDB, err := sql.Open("sqlite3", ":memory:")
		if err != nil {
			t.Fatalf("Failed to create temporary database: %v", err)
		}
		defer tempDB.Close()
		db = tempDB
		setupDatabase()

		// Ensure there are no errors
		assert.NotNil(t, db, "Database is nil after setupDatabase")
	})

	// Test setting up the database
	t.Run("SetupDatabase", func(t *testing.T) {
		// Check if the table is created
		rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name='keys';")
		assert.NoError(t, err, "Error checking for table existence")
		defer rows.Close()
		assert.True(t, rows.Next(), "Table 'keys' not found")
	})
}

func TestGenKeys(t *testing.T) {
	// Run genKeys function
	genKeys()
	// Add test logic if needed
}


func TestStoreKey(t *testing.T) {
	// Initialize the database
	setupDatabase()
	if db == nil {
		t.Fatal("Error setting up the database")
	}

	// Generate keys
	genKeys()
	if goodPrivKey == nil {
		t.Fatal("Error generating keys")
	}

	// Ensure that goodPrivKey is not nil
	if goodPrivKey == nil {
		t.Fatal("goodPrivKey is nil")
	}

	// Run storeKey with a valid private key
	storeKey(goodPrivKey, time.Now().Unix())
	var storedKey []byte
	var storedExp int64
	err := db.QueryRow("SELECT key, exp FROM keys").Scan(&storedKey, &storedExp)
	if err != nil {
		t.Fatalf("Error querying stored key: %v", err)
	}

	assert.NotNil(t, storedKey, "Stored key is nil")
	assert.Greater(t, storedExp, int64(0), "Stored expiration time is not valid")
}

func TestSerializeAndDeserializeKey(t *testing.T) {
	// Run serializeKey and deserializeKey functions
	key := goodPrivKey
	serialized := serializeKey(key)
	deserialized, err := deserializeKey(serialized)
	assert.NoError(t, err, "Error deserializing key")
	assert.Equal(t, key.D, deserialized.D, "Deserialized key does not match original key")
}

func TestAuthHandler(t *testing.T) {
	// Test expired case
	t.Run("ExpiredCase", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/auth?expired=true", nil)
		assert.NoError(t, err, "Error creating request")
		rr := httptest.NewRecorder()
		AuthHandler(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "Unexpected status code")

	})

	// Test non-expired case
	t.Run("NonExpiredCase", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/auth?expired=false", nil)
		assert.NoError(t, err, "Error creating request")
		rr := httptest.NewRecorder()
		AuthHandler(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "Unexpected status code")
	})
}


func TestJWKSHandler(t *testing.T) {
	// Test valid GET request
	t.Run("ValidGETRequest", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/.well-known/jwks.json", nil)
		assert.NoError(t, err, "Error creating request")
		rr := httptest.NewRecorder()
		JWKSHandler(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "Unexpected status code")
	})
}

func TestGetKeysFromDatabase(t *testing.T) {
	// Test getKeyFromDatabase for expired case
	t.Run("GetExpiredKeyFromDatabase", func(t *testing.T) {
		keyData, exp, kid, err := getKeyFromDatabase(true)
		assert.NoError(t, err, "Error getting expired key from database")
		assert.NotNil(t, keyData, "Key data is nil")
		assert.Greater(t, exp, int64(0), "Expiration time is not valid")
		assert.Greater(t, kid, 0, "Kid is not valid")
	})

	// Test getKeyFromDatabase for non-expired case
	t.Run("GetNonExpiredKeyFromDatabase", func(t *testing.T) {
		keyData, exp, kid, err := getKeyFromDatabase(false)
		assert.NoError(t, err, "Error getting non-expired key from database")
		assert.NotNil(t, keyData, "Key data is nil")
		assert.Greater(t, exp, int64(0), "Expiration time is not valid")
		assert.Greater(t, kid, 0, "Kid is not valid")
	})
}

func TestHTTPRequests(t *testing.T) {
	t.Run("AuthHandler_ValidRequest", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/auth", nil)
		assert.NoError(t, err, "Error creating request")
		rr := httptest.NewRecorder()
		AuthHandler(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "Unexpected status code")
	})
}

func TestAll(t *testing.T) {
    t.Run("SetupDatabase", TestSetupDatabase)
    t.Run("GenKeys", TestGenKeys)
    t.Run("StoreKey", TestStoreKey)
    t.Run("SerializeAndDeserializeKey", TestSerializeAndDeserializeKey)
    t.Run("AuthHandler", TestAuthHandler)
    t.Run("JWKSHandler", TestJWKSHandler)
    t.Run("GetKeysFromDatabase", TestGetKeysFromDatabase)
    t.Run("HTTPRequests", TestHTTPRequests)

    genKeys()
}
