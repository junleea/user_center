package service

import (
	"fmt"
	"testing"
	"time"
	"user_center/dao"
	"user_center/proto"
	"user_center/worker" // Ensure worker is imported to allow function replacement

	"github.com/golang-jwt/jwt/v4"
)

// Mock Redis Store
var mockRedisStore = make(map[string]string)
var mockRedisExpire = make(map[string]time.Time)

// Ensure original functions are stored to be restored
var (
	originalSetRedisWithExpire func(key string, value string, expire time.Duration) bool
	originalIsContainKey       func(key string) bool
	// Add original DAO functions here if you mock them similarly
)

func setupGlobalMocks() {
	originalSetRedisWithExpire = worker.SetRedisWithExpire
	originalIsContainKey = worker.IsContainKey

	worker.SetRedisWithExpire = func(key string, value string, expire time.Duration) bool {
		mockRedisStore[key] = value
		if expire > 0 {
			mockRedisExpire[key] = time.Now().Add(expire)
		}
		return true
	}
	worker.IsContainKey = func(key string) bool {
		expiry, exists := mockRedisExpire[key]
		if exists && time.Now().After(expiry) {
			delete(mockRedisStore, key)
			delete(mockRedisExpire, key)
			return false
		}
		_, ok := mockRedisStore[key]
		return ok
	}
}

func teardownGlobalMocks() {
	worker.SetRedisWithExpire = originalSetRedisWithExpire
	worker.IsContainKey = originalIsContainKey
}

// Helper to reset mock stores between tests
func resetMockStores() {
	mockRedisStore = make(map[string]string)
	mockRedisExpire = make(map[string]time.Time)
}

func init() {
	// IMPORTANT: This is a placeholder for test key.
	// In a real application, manage your keys securely and consistently.
	proto.SigningKey = []byte("test-signing-key-that-is-long-enough-for-hs256")
	// Note: AccessTokenDuration and RefreshTokenDuration are constants in proto/types.go
	// and should be available directly.
}

func TestGenerateAuthTokens(t *testing.T) {
	setupGlobalMocks()
	defer teardownGlobalMocks()
	resetMockStores()

	testUser := dao.User{
		ID:   1,
		Name: "testuser",
	}

	accessTokenString, refreshTokenString, err := GenerateAuthTokens(testUser)

	if err != nil {
		t.Fatalf("GenerateAuthTokens returned an error: %v", err)
	}

	if accessTokenString == "" {
		t.Errorf("Expected non-empty access_token, got empty string")
	}
	if refreshTokenString == "" {
		t.Errorf("Expected non-empty refresh_token, got empty string")
	}

	// Verify Access Token
	accessTokenClaims := jwt.MapClaims{}
	accessToken, err := jwt.ParseWithClaims(accessTokenString, accessTokenClaims, func(token *jwt.Token) (interface{}, error) {
		return proto.SigningKey, nil
	})
	if err != nil {
		t.Fatalf("Failed to parse access_token: %v", err)
	}
	if !accessToken.Valid {
		t.Errorf("Access token is not valid")
	}

	if val, ok := accessTokenClaims["username"].(string); !ok || val != testUser.Name {
		t.Errorf("Access token username claim mismatch: expected %s, got %v", testUser.Name, accessTokenClaims["username"])
	}
	if val, ok := accessTokenClaims["id"].(float64); !ok || uint(val) != testUser.ID { // JWT parses numbers as float64
		t.Errorf("Access token id claim mismatch: expected %d, got %v", testUser.ID, accessTokenClaims["id"])
	}
	if _, expOk := accessTokenClaims["exp"].(float64); !expOk {
		t.Errorf("Access token exp claim is missing or not a number")
	} else {
		// Optional: Check if expiry is roughly correct
		expTimestamp := int64(accessTokenClaims["exp"].(float64))
		expectedExp := time.Now().Add(proto.AccessTokenDuration).Unix()
		if expTimestamp < time.Now().Unix() || expTimestamp > expectedExp+60 { // allow 60s buffer
			t.Errorf("Access token expiry time mismatch: expected around %v, got %v", expectedExp, expTimestamp)
		}
	}


	// Verify Refresh Token
	refreshTokenClaims := jwt.MapClaims{}
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, refreshTokenClaims, func(token *jwt.Token) (interface{}, error) {
		return proto.SigningKey, nil
	})
	if err != nil {
		t.Fatalf("Failed to parse refresh_token: %v", err)
	}
	if !refreshToken.Valid {
		t.Errorf("Refresh token is not valid")
	}
	if val, ok := refreshTokenClaims["id"].(float64); !ok || uint(val) != testUser.ID {
		t.Errorf("Refresh token id claim mismatch: expected %d, got %v", testUser.ID, refreshTokenClaims["id"])
	}
	if _, expOk := refreshTokenClaims["exp"].(float64); !expOk {
		t.Errorf("Refresh token exp claim is missing or not a number")
	} else {
		// Optional: Check if expiry is roughly correct
		expTimestamp := int64(refreshTokenClaims["exp"].(float64))
		expectedExp := time.Now().Add(proto.RefreshTokenDuration).Unix()
		if expTimestamp < time.Now().Unix() || expTimestamp > expectedExp+60 { // allow 60s buffer
			t.Errorf("Refresh token expiry time mismatch: expected around %v, got %v", expectedExp, expTimestamp)
		}
	}


	// Verify Redis storage
	expectedRedisKey := fmt.Sprintf("refresh_token:%d:%s", testUser.ID, refreshTokenString)
	if !worker.IsContainKey(expectedRedisKey) { // Uses our mock
		t.Errorf("Refresh token not found in mock Redis store with key: %s. Store: %v", expectedRedisKey, mockRedisStore)
	}
	
	if expiryTime, found := mockRedisExpire[expectedRedisKey]; !found {
		t.Errorf("Refresh token does not have an expiry set in mock Redis")
	} else {
		expectedExpiryLowerBound := time.Now().Add(proto.RefreshTokenDuration - time.Minute) // Allow for slight timing diff
		expectedExpiryUpperBound := time.Now().Add(proto.RefreshTokenDuration + time.Minute)
		if expiryTime.Before(expectedExpiryLowerBound) || expiryTime.After(expectedExpiryUpperBound) {
			t.Errorf("Refresh token expiry time mismatch: expected around %v (+/-1m), got %v", time.Now().Add(proto.RefreshTokenDuration), expiryTime)
		}
	}
}

// For DAO mocking, we'll define a replaceable function within the test file itself
// if we cannot modify the original dao package to use interfaces + DI easily.
var mockFindUserByID2 func(id int) dao.User // Used by specific subtests
var mockWorkerGetRedis func(key string) string // For GetUserByIDWithCache if needed

func TestValidateRefreshTokenAndCreateNewAccessToken(t *testing.T) {
	setupGlobalMocks() // Sets up Redis mocks (IsContainKey, SetRedisWithExpire)
	
	originalDAOFindUserByID2 := dao.FindUserByID2 
	defer func() {
		dao.FindUserByID2 = originalDAOFindUserByID2 
		teardownGlobalMocks() 
	}()
	
	dao.FindUserByID2 = func(id int) dao.User { 
		if mockFindUserByID2 != nil {
			return mockFindUserByID2(id)
		}
		t.Fatalf("dao.FindUserByID2 called without specific mockFindUserByID2 being set in test")
		return dao.User{}
	}

	baseUser := dao.User{ID: 1, Name: "refresher", Email: "refresh@example.com"}

	generateTestRefreshToken := func(user dao.User, duration time.Duration, key []byte) string {
		claims := jwt.MapClaims{
			"id":  float64(user.ID), 
			"exp": time.Now().Add(duration).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("Failed to generate test refresh token: %v", err)
		}
		return tokenString
	}

	t.Run("ValidRefreshToken", func(t *testing.T) {
		resetMockStores()
		mockFindUserByID2 = func(id int) dao.User { 
			if uint(id) == baseUser.ID {
				return baseUser
			}
			return dao.User{}
		}

		validRefreshToken := generateTestRefreshToken(baseUser, proto.RefreshTokenDuration, proto.SigningKey)
		redisKey := fmt.Sprintf("refresh_token:%d:%s", baseUser.ID, validRefreshToken)
		worker.SetRedisWithExpire(redisKey, "active", proto.RefreshTokenDuration) // Mock SetRedisWithExpire is called by setupGlobalMocks

		newAccessToken, err := ValidateRefreshTokenAndCreateNewAccessToken(validRefreshToken)

		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if newAccessToken == "" {
			t.Errorf("Expected a new access token, got empty string")
		}

		accessTokenClaims := jwt.MapClaims{}
		parsedToken, err := jwt.ParseWithClaims(newAccessToken, accessTokenClaims, func(token *jwt.Token) (interface{}, error) {
			return proto.SigningKey, nil
		})
		if err != nil {
			t.Fatalf("Failed to parse new access token: %v", err)
		}
		if !parsedToken.Valid {
			t.Errorf("New access token is not valid")
		}
		if val, ok := accessTokenClaims["username"].(string); !ok || val != baseUser.Name {
			t.Errorf("New access token username claim mismatch: expected %s, got %v", baseUser.Name, accessTokenClaims["username"])
		}
		if val, ok := accessTokenClaims["id"].(float64); !ok || uint(val) != baseUser.ID {
			t.Errorf("New access token id claim mismatch: expected %d, got %v", baseUser.ID, accessTokenClaims["id"])
		}
		if !worker.IsContainKey(redisKey) { // Mock IsContainKey is called by setupGlobalMocks
			t.Errorf("Original refresh token was removed from Redis, but should not have been. Store: %v", mockRedisStore)
		}
	})

	t.Run("MalformedRefreshToken", func(t *testing.T) {
		resetMockStores()
		_, err := ValidateRefreshTokenAndCreateNewAccessToken("this.is.not.a.jwt")
		if err == nil {
			t.Errorf("Expected error for malformed token, got nil")
		}
	})

	t.Run("ExpiredRefreshToken", func(t *testing.T) {
		resetMockStores()
		expiredToken := generateTestRefreshToken(baseUser, -time.Hour, proto.SigningKey) 
		_, err := ValidateRefreshTokenAndCreateNewAccessToken(expiredToken)
		if err == nil {
			t.Errorf("Expected error for expired token, got nil")
		}
	})

	t.Run("RefreshTokenNotInRedis", func(t *testing.T) {
		resetMockStores() 
		mockFindUserByID2 = func(id int) dao.User { return baseUser } 

		tokenNotInRedis := generateTestRefreshToken(baseUser, proto.RefreshTokenDuration, proto.SigningKey)
		
		_, err := ValidateRefreshTokenAndCreateNewAccessToken(tokenNotInRedis)
		if err == nil {
			t.Errorf("Expected error for token not in Redis, got nil")
		} else if !strings.Contains(err.Error(), "refresh token not found in Redis or has expired") {
            t.Errorf("Expected specific error for token not in Redis, got: %s", err.Error())
        }
	})

	t.Run("UserNotFoundForTokenID", func(t *testing.T) {
		resetMockStores()
		mockFindUserByID2 = func(id int) dao.User { 
			return dao.User{} 
		}

		userNotFoundToken := generateTestRefreshToken(baseUser, proto.RefreshTokenDuration, proto.SigningKey)
		redisKey := fmt.Sprintf("refresh_token:%d:%s", baseUser.ID, userNotFoundToken)
		worker.SetRedisWithExpire(redisKey, "active", proto.RefreshTokenDuration)

		_, err := ValidateRefreshTokenAndCreateNewAccessToken(userNotFoundToken)
		if err == nil {
			t.Errorf("Expected error for user not found, got nil")
		} else if !strings.Contains(err.Error(), "user not found") {
             t.Errorf("Expected specific error for user not found, got: %s", err.Error())
        }
	})
    
    t.Run("InvalidSigningMethodInRefreshToken", func(t *testing.T) {
		resetMockStores()
        validTokenStr := generateTestRefreshToken(baseUser, proto.RefreshTokenDuration, proto.SigningKey)
        parts := strings.Split(validTokenStr, ".")
        if len(parts) != 3 {
            t.Fatalf("Failed to split token into parts for tampering")
        }
        fakeHeader := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9" // {"alg":"ES256","typ":"JWT"}
        tamperedTokenStr := fakeHeader + "." + parts[1] + "." + parts[2]

		_, err := ValidateRefreshTokenAndCreateNewAccessToken(tamperedTokenStr)
		if err == nil {
			t.Errorf("Expected error for invalid signing method, got nil")
		} else if !strings.Contains(err.Error(), "unexpected signing method") {
			t.Errorf("Expected 'unexpected signing method' error, got: %s", err.Error())
		}
	})

    t.Run("InvalidUserIDClaimInRefreshToken", func(t *testing.T) {
		resetMockStores()
        claims := jwt.MapClaims{
			"id":  "not_a_number", 
			"exp": time.Now().Add(proto.RefreshTokenDuration).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString(proto.SigningKey)

		_, err := ValidateRefreshTokenAndCreateNewAccessToken(tokenString)
		if err == nil {
			t.Errorf("Expected error for invalid user ID claim, got nil")
		} else if !strings.Contains(err.Error(), "invalid user ID in refresh token claims") {
			t.Errorf("Expected 'invalid user ID in refresh token claims' error, got: %s", err.Error())
		}
	})
}

func TestGetUserInfoByToken(t *testing.T) {
	setupGlobalMocks() 
	originalDAOFindUserByID2_GetInfo := dao.FindUserByID2 // Use a distinct var name to avoid conflict if tests run concurrently (though t.Run helps)
	dao.FindUserByID2 = func(id int) dao.User {
		if mockFindUserByID2 != nil { // mockFindUserByID2 is test-scoped
			return mockFindUserByID2(id)
		}
		t.Fatalf("dao.FindUserByID2 mock not set for GetUserInfoByToken test")
		return dao.User{}
	}
	// Mock for GetRedis used by GetUserByIDWithCache
	originalWorkerGetRedis_GetInfo := worker.GetRedis
	worker.GetRedis = func(key string) string {
		if mockWorkerGetRedis != nil { // mockWorkerGetRedis is test-scoped
			return mockWorkerGetRedis(key)
		}
		return "" // Default to cache miss
	}

	defer func() {
		dao.FindUserByID2 = originalDAOFindUserByID2_GetInfo
		worker.GetRedis = originalWorkerGetRedis_GetInfo
		teardownGlobalMocks()
	}()

	testUser := dao.User{ID: 1, Name: "tokenuser", Email: "token@example.com", Password: "hashedpassword"}

	generateTestAccessToken := func(user dao.User, duration time.Duration, key []byte, includeID bool, idValue interface{}, includeUsername bool, usernameValue interface{}) string {
		claims := jwt.MapClaims{
			"exp": time.Now().Add(duration).Unix(),
		}
		if includeID { claims["id"] = idValue; }
		if includeUsername { claims["username"] = usernameValue; }
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(key)
		if err != nil { t.Fatalf("Failed to generate test access token: %v", err); }
		return tokenString
	}

	t.Run("ValidAccessToken", func(t *testing.T) {
		resetMockStores()
		mockFindUserByID2 = func(id int) dao.User { // Specific mock for this sub-test
			if uint(id) == testUser.ID { return testUser; }
			return dao.User{}
		}
		mockWorkerGetRedis = func(key string) string { return "" } // Cache miss

		validAccessToken := generateTestAccessToken(testUser, proto.AccessTokenDuration, proto.SigningKey, true, float64(testUser.ID), true, testUser.Name)
		
		retrievedUser, err := GetUserInfoByToken(validAccessToken)
		if err != nil { t.Fatalf("Expected no error, got %v", err); }
		if retrievedUser.ID != testUser.ID { t.Errorf("Expected user ID %d, got %d", testUser.ID, retrievedUser.ID); }
		if retrievedUser.Name != testUser.Name { t.Errorf("Expected user name %s, got %s", testUser.Name, retrievedUser.Name); }
		if retrievedUser.Password != "" { t.Errorf("Expected password to be cleared, got '%s'", retrievedUser.Password); }
	})

	t.Run("MalformedAccessToken", func(t *testing.T) {
		resetMockStores()
		_, err := GetUserInfoByToken("not.a.valid.token")
		if err == nil { t.Errorf("Expected error for malformed token, got nil"); }
	})

	t.Run("ExpiredAccessToken", func(t *testing.T) {
		resetMockStores()
		expiredToken := generateTestAccessToken(testUser, -time.Hour, proto.SigningKey, true, float64(testUser.ID), true, testUser.Name)
		_, err := GetUserInfoByToken(expiredToken)
		if err == nil { t.Errorf("Expected error for expired token, got nil"); }
		if !strings.Contains(err.Error(), "token is invalid") && !strings.Contains(err.Error(), "token has invalid claims: token is expired") {
            t.Errorf("Expected 'token is invalid' or 'expired' error, got: %v", err)
        }
	})

	t.Run("TokenValidUserNotFound", func(t *testing.T) {
		resetMockStores()
		mockFindUserByID2 = func(id int) dao.User { return dao.User{}; } // User not found
		mockWorkerGetRedis = func(key string) string { return "" } // Cache miss

		validToken := generateTestAccessToken(dao.User{ID: 999}, proto.AccessTokenDuration, proto.SigningKey, true, float64(999), true, "ghost")
		_, err := GetUserInfoByToken(validToken)
		if err == nil { t.Errorf("Expected error for user not found, got nil"); }
		if !strings.Contains(err.Error(), "user not found") { t.Errorf("Expected 'user not found' error, got: %v", err.Error()); }
	})
    
    t.Run("TokenMissingIDClaim", func(t *testing.T) {
        resetMockStores()
        token := generateTestAccessToken(testUser, proto.AccessTokenDuration, proto.SigningKey, false, nil, true, testUser.Name)
        _, err := GetUserInfoByToken(token)
        if err == nil { t.Errorf("Expected error for token missing 'id' claim, got nil"); }
    })

    t.Run("TokenInvalidIDClaimType", func(t *testing.T) {
        resetMockStores()
        token := generateTestAccessToken(testUser, proto.AccessTokenDuration, proto.SigningKey, true, "not_a_number_id", true, testUser.Name)
        _, err := GetUserInfoByToken(token)
        if err == nil { t.Errorf("Expected error for token with invalid 'id' claim type, got nil"); }
    })
}
// var originalFindUserByID2 func(id int) dao.User

// func mockFindUserByID2(id int) dao.User {
// 	if id == 1 { // Example user
// 		return dao.User{ID: 1, Name: "testuser", Email: "test@example.com"}
// 	}
// 	return dao.User{}
// }

// In setupGlobalMocks:
// originalFindUserByID2 = dao.FindUserByID2 // If FindUserByID2 is a package-level func
// dao.FindUserByID2 = mockFindUserByID2

// In teardownGlobalMocks:
// dao.FindUserByID2 = originalFindUserByID2
