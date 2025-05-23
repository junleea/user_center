package handler

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"user_center/dao"
	"user_center/proto"
	"user_center/service"

	"github.com/gin-gonic/gin"
)

// --- Mock Service Layer ---
// We'll replace actual service functions with these mocks during tests.
var (
	originalGetUser                               func(name, email, password string) dao.User
	originalGenerateAuthTokens                func(user dao.User) (string, string, error)
	originalContainsUser                      func(name, email string) bool
	originalCreateUser                        func(name, password, email, gender string, age int) uint
	originalGetUserByIDWithCache              func(id int) dao.User
	originalValidateRefreshTokenAndCreateNewAccessToken func(refreshTokenString string) (string, error)
	// If GetUserInfo handler calls a service function like service.GetUserByID directly, mock that too.
	// For now, GetUserInfo handler uses dao.FindUserByID2, which is harder to mock without DI in DAO.
	// We might need to adjust GetUserInfo test or its implementation if direct DAO calls are problematic for tests.
	originalWorkerGetRedis func(key string) string // For register_code
)

// Mock implementations
var (
	mockServiceGetUser                               func(name, email, password string) dao.User
	mockServiceGenerateAuthTokens                func(user dao.User) (string, string, error)
	mockServiceContainsUser                      func(name, email string) bool
	mockServiceCreateUser                        func(name, password, email, gender string, age int) uint
	mockServiceGetUserByIDWithCache              func(id int) dao.User
	mockServiceValidateRefreshTokenAndCreateNewAccessToken func(refreshTokenString string) (string, error)
	mockWorkerGetRedis                           func(key string) string // For register_code
)

func setupServiceMocks() { // Renamed to avoid confusion with individual test setups
	originalGetUser = service.GetUser
	service.GetUser = func(name, email, password string) dao.User {
		if mockServiceGetUser != nil {
			return mockServiceGetUser(name, email, password)
		}
		panic("service.GetUser mock not set")
	}

	originalGenerateAuthTokens = service.GenerateAuthTokens
	service.GenerateAuthTokens = func(user dao.User) (string, string, error) {
		if mockServiceGenerateAuthTokens != nil {
			return mockServiceGenerateAuthTokens(user)
		}
		panic("service.GenerateAuthTokens mock not set")
	}

	originalContainsUser = service.ContainsUser
	service.ContainsUser = func(name, email string) bool {
		if mockServiceContainsUser != nil {
			return mockServiceContainsUser(name, email)
		}
		panic("service.ContainsUser mock not set")
	}

	originalCreateUser = service.CreateUser
	service.CreateUser = func(name, password, email, gender string, age int) uint {
		if mockServiceCreateUser != nil {
			return mockServiceCreateUser(name, password, email, gender, age)
		}
		panic("service.CreateUser mock not set")
	}
	
	originalGetUserByIDWithCache = service.GetUserByIDWithCache
	service.GetUserByIDWithCache = func(id int) dao.User {
	    if mockServiceGetUserByIDWithCache != nil {
	        return mockServiceGetUserByIDWithCache(id)
	    }
	    panic("service.GetUserByIDWithCache mock not set")
	}

	originalValidateRefreshTokenAndCreateNewAccessToken = service.ValidateRefreshTokenAndCreateNewAccessToken
	service.ValidateRefreshTokenAndCreateNewAccessToken = func(refreshTokenString string) (string, error) {
		if mockServiceValidateRefreshTokenAndCreateNewAccessToken != nil {
			return mockServiceValidateRefreshTokenAndCreateNewAccessToken(refreshTokenString)
		}
		panic("service.ValidateRefreshTokenAndCreateNewAccessToken mock not set")
	}

	// Mock worker.GetRedis
	originalWorkerGetRedis = worker.GetRedis
	worker.GetRedis = func(key string) string {
		if mockWorkerGetRedis != nil {
			return mockWorkerGetRedis(key)
		}
		// Return empty string by default if not specifically mocked,
		// which would typically cause "code invalid" or similar.
		// For some tests, this default might be acceptable.
		// For others, mockWorkerGetRedis needs to be explicitly set.
		return "" 
	}
}

func teardownServiceMocks() {
	service.GetUser = originalGetUser
	service.GenerateAuthTokens = originalGenerateAuthTokens
	service.ContainsUser = originalContainsUser
	service.CreateUser = originalCreateUser
	service.GetUserByIDWithCache = originalGetUserByIDWithCache
	service.ValidateRefreshTokenAndCreateNewAccessToken = originalValidateRefreshTokenAndCreateNewAccessToken
	worker.GetRedis = originalWorkerGetRedis // Restore worker.GetRedis
}

// --- Gin Test Setup ---
func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New() // Use gin.New() instead of gin.Default() to avoid default middleware in tests
	SetUpUserGroup(router) // This function is in handler/user.go and sets up the routes
	return router
}

// Initialize proto.SigningKey for tests
func init() {
	proto.SigningKey = []byte("test-signing-key-that-is-long-enough-for-hs256")
	// Initialize worker's Redis client for any indirect calls if necessary,
	// though direct calls are preferably mocked at the service level.
	// e.g. worker.InitRedis() if some part of the handler path might touch it
	// and isn't fully mocked out. For now, assuming service mocks cover Redis interactions.
}


// --- Test Cases ---

func TestLoginHandler_Success(t *testing.T) {
	setupServiceMocks()
	defer teardownServiceMocks()

	router := setupTestRouter()

	mockUser := dao.User{ID: 1, Name: "testlogin", Email: "login@example.com", Password: "hashedpassword"}
	mockAccessToken := "mock_access_token_login"
	mockRefreshToken := "mock_refresh_token_login"

	mockServiceGetUser = func(name, email, password string) dao.User {
		// Simulate password hashing for comparison if necessary, or assume input password is already hashed
		// For this test, let's assume the input password to GetUser is the hashed one or GetUser handles it.
		// The RLReq struct takes plain password, which is then hashed in the handler.
		hasher := md5.New()
		hasher.Write([]byte("password123"))
		hashedPassword := hex.EncodeToString(hasher.Sum(nil))

		if (name == mockUser.Name || email == mockUser.Email) && password == hashedPassword {
			return mockUser
		}
		return dao.User{}
	}
	mockServiceGenerateAuthTokens = func(user dao.User) (string, string, error) {
		if user.ID == mockUser.ID {
			return mockAccessToken, mockRefreshToken, nil
		}
		return "", "", errors.New("user mismatch in token generation mock")
	}

	loginPayload := RLReq{
		User:     "testlogin",
		Password: "password123", // Plain password
	}
	payloadBytes, _ := json.Marshal(loginPayload)

	req, _ := http.NewRequest(http.MethodPost, "/user/login", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v. Body: %s",
			status, http.StatusOK, rr.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Could not parse response JSON: %v", err)
	}

	if int(response["code"].(float64)) != proto.SuccessCode {
		t.Errorf("Expected success code %d, got %v", proto.SuccessCode, response["code"])
	}

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Response data is not of expected type map[string]interface{}")
	}

	if data["access_token"] != mockAccessToken {
		t.Errorf("Expected access_token %s, got %v", mockAccessToken, data["access_token"])
	}
	if data["refresh_token"] != mockRefreshToken {
		t.Errorf("Expected refresh_token %s, got %v", mockRefreshToken, data["refresh_token"])
	}
	if uint(data["user_id"].(float64)) != mockUser.ID {
		t.Errorf("Expected user_id %d, got %v", mockUser.ID, data["user_id"])
	}
	if data["username"] != mockUser.Name {
		t.Errorf("Expected username %s, got %v", mockUser.Name, data["username"])
	}
}

func TestLoginHandler_UserNotFound(t *testing.T) {
	setupServiceMocks()
	defer teardownServiceMocks()
	router := setupTestRouter()

	mockServiceGetUser = func(name, email, password string) dao.User {
		return dao.User{} // Simulate user not found
	}
	// GenerateAuthTokens should not be called in this case

	loginPayload := RLReq{User: "unknownuser", Password: "password123"}
	payloadBytes, _ := json.Marshal(loginPayload)
	req, _ := http.NewRequest(http.MethodPost, "/user/login", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK { // Handler returns 200 for this custom error
		t.Errorf("handler returned wrong status code: got %v want %v. Body: %s",
			status, http.StatusOK, rr.Body.String())
	}
	var response map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &response)
	if int(response["code"].(float64)) != proto.UsernameOrPasswordError {
		t.Errorf("Expected error code %d, got %v", proto.UsernameOrPasswordError, response["code"])
	}
}

func TestLoginHandler_TokenGenerationError(t *testing.T) {
    setupServiceMocks()
    defer teardownServiceMocks()
    router := setupTestRouter()

    mockUser := dao.User{ID: 1, Name: "testlogin", Email: "login@example.com", Password: "hashedpassword"}
    
    mockServiceGetUser = func(name, email, password string) dao.User {
        hasher := md5.New()
		hasher.Write([]byte("password123"))
		hashedPassword := hex.EncodeToString(hasher.Sum(nil))
        if (name == mockUser.Name || email == mockUser.Email) && password == hashedPassword {
			return mockUser
		}
		return dao.User{}
    }
    mockServiceGenerateAuthTokens = func(user dao.User) (string, string, error) {
        return "", "", errors.New("failed to generate tokens") // Simulate token generation error
    }

    loginPayload := RLReq{User: "testlogin", Password: "password123"}
    payloadBytes, _ := json.Marshal(loginPayload)
    req, _ := http.NewRequest(http.MethodPost, "/user/login", bytes.NewBuffer(payloadBytes))
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusInternalServerError {
        t.Errorf("handler returned wrong status code: got %v want %v. Body: %s",
            status, http.StatusInternalServerError, rr.Body.String())
    }
    var response map[string]interface{}
    json.Unmarshal(rr.Body.Bytes(), &response)
    if int(response["code"].(float64)) != proto.TokenGenerationError {
        t.Errorf("Expected error code %d for token generation failure, got %v", proto.TokenGenerationError, response["code"])
    }
}


func TestRegisterHandlerV2_Success(t *testing.T) {
	setupServiceMocks()
	defer teardownServiceMocks()
	router := setupTestRouter()

	regDetails := RLReq{
		User:     "newuser",
		Email:    "new@example.com",
		Password: "password123",
		Code:     "123456",
		Gender:   "male",
		Age:      25,
	}
	hashedPassword := func(s string) string {
		h := md5.New()
		h.Write([]byte(s))
		return hex.EncodeToString(h.Sum(nil))
	}(regDetails.Password)

	createdUserID := uint(5)
	createdUserDAO := dao.User{ID: createdUserID, Name: regDetails.User, Email: regDetails.Email, Password: hashedPassword, Gender: regDetails.Gender, Age: regDetails.Age}
	mockAccessToken := "mock_access_token_reg"
	mockRefreshToken := "mock_refresh_token_reg"

	mockWorkerGetRedis = func(key string) string {
		if key == "register_code_"+regDetails.Email {
			return regDetails.Code // Valid code
		}
		return ""
	}
	mockServiceContainsUser = func(name, email string) bool { return false }
	mockServiceCreateUser = func(name, password, email, gender string, age int) uint {
		if name == regDetails.User && password == hashedPassword && email == regDetails.Email {
			return createdUserID
		}
		return 0
	}
	mockServiceGetUserByIDWithCache = func(id int) dao.User {
		if uint(id) == createdUserID {
			return createdUserDAO
		}
		return dao.User{}
	}
	mockServiceGenerateAuthTokens = func(user dao.User) (string, string, error) {
		if user.ID == createdUserID {
			return mockAccessToken, mockRefreshToken, nil
		}
		return "", "", errors.New("user mismatch for token gen")
	}

	payloadBytes, _ := json.Marshal(regDetails)
	req, _ := http.NewRequest(http.MethodPost, "/user/register", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v. Body: %s", status, http.StatusOK, rr.Body.String())
	}

	var resp proto.GenerateResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Could not parse response JSON: %v", err)
	}

	if resp.Code != proto.SuccessCode {
		t.Errorf("Expected success code %d, got %d. Message: %s", proto.SuccessCode, resp.Code, resp.Message)
	}

	authResp, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Response data is not map[string]interface{}, got %T: %v", resp.Data, resp.Data)
	}

	if authResp["access_token"] != mockAccessToken {
		t.Errorf("Expected access_token %s, got %v", mockAccessToken, authResp["access_token"])
	}
	if authResp["refresh_token"] != mockRefreshToken {
		t.Errorf("Expected refresh_token %s, got %v", mockRefreshToken, authResp["refresh_token"])
	}
	if uint(authResp["user_id"].(float64)) != createdUserID {
		t.Errorf("Expected user_id %d, got %v", createdUserID, authResp["user_id"])
	}
}

func TestRegisterHandlerV2_UserExists(t *testing.T) {
	setupServiceMocks()
	defer teardownServiceMocks()
	router := setupTestRouter()

	regDetails := RLReq{User: "existinguser", Email: "exists@example.com", Password: "password123", Code: "123456"}
	mockWorkerGetRedis = func(key string) string { return regDetails.Code } // Valid code
	mockServiceContainsUser = func(name, email string) bool { return true } // User exists

	payloadBytes, _ := json.Marshal(regDetails)
	req, _ := http.NewRequest(http.MethodPost, "/user/register", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp proto.GenerateResp
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Code != proto.UsernameExists {
		t.Errorf("Expected code %d (UsernameExists), got %d. Message: %s", proto.UsernameExists, resp.Code, resp.Message)
	}
}

func TestRegisterHandlerV2_InvalidCode(t *testing.T) {
	setupServiceMocks()
	defer teardownServiceMocks()
	router := setupTestRouter()

	regDetails := RLReq{User: "newuser", Email: "new@example.com", Password: "password123", Code: "wrongcode"}
	mockWorkerGetRedis = func(key string) string { return "correctcode" } // Different code in Redis

	payloadBytes, _ := json.Marshal(regDetails)
	req, _ := http.NewRequest(http.MethodPost, "/user/register", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp proto.GenerateResp
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Code != proto.OperationFailed || !strings.Contains(resp.Message, "验证码错误") { // Assuming OperationFailed is used for this
		t.Errorf("Expected code %d (OperationFailed) and '验证码错误' message, got code %d, message '%s'", proto.OperationFailed, resp.Code, resp.Message)
	}
}

func TestRegisterHandlerV2_CreateUserFails(t *testing.T) {
    setupServiceMocks()
    defer teardownServiceMocks()
    router := setupTestRouter()

    regDetails := RLReq{User: "newuser", Email: "new@example.com", Password: "password123", Code: "123456"}
    hashedPassword := func(s string) string { h := md5.New(); h.Write([]byte(s)); return hex.EncodeToString(h.Sum(nil)) }(regDetails.Password)

    mockWorkerGetRedis = func(key string) string { return regDetails.Code }
    mockServiceContainsUser = func(name, email string) bool { return false }
    mockServiceCreateUser = func(name, password, email, gender string, age int) uint { return 0 } // CreateUser fails

    payloadBytes, _ := json.Marshal(regDetails)
    req, _ := http.NewRequest(http.MethodPost, "/user/register", bytes.NewBuffer(payloadBytes))
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    var resp proto.GenerateResp
    json.Unmarshal(rr.Body.Bytes(), &resp)
    if resp.Code != proto.OperationFailed || !strings.Contains(resp.Message, "创建用户失败") {
        t.Errorf("Expected code %d (OperationFailed) and '创建用户失败' message, got code %d, message '%s'", proto.OperationFailed, resp.Code, resp.Message)
    }
}

func TestRegisterHandlerV2_GetUserByIDWithCacheFails(t *testing.T) {
    setupServiceMocks()
    defer teardownServiceMocks()
    router := setupTestRouter()

    regDetails := RLReq{User: "newuser", Email: "new@example.com", Password: "password123", Code: "123456"}
    hashedPassword := func(s string) string { h := md5.New(); h.Write([]byte(s)); return hex.EncodeToString(h.Sum(nil)) }(regDetails.Password)
    createdUserID := uint(6)

    mockWorkerGetRedis = func(key string) string { return regDetails.Code }
    mockServiceContainsUser = func(name, email string) bool { return false }
    mockServiceCreateUser = func(name, password, email, gender string, age int) uint { return createdUserID }
    mockServiceGetUserByIDWithCache = func(id int) dao.User { return dao.User{} } // GetUserByIDWithCache fails

    payloadBytes, _ := json.Marshal(regDetails)
    req, _ := http.NewRequest(http.MethodPost, "/user/register", bytes.NewBuffer(payloadBytes))
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    var resp proto.GenerateResp
    json.Unmarshal(rr.Body.Bytes(), &resp)
    if resp.Code != proto.OperationFailed || !strings.Contains(resp.Message, "Failed to retrieve created user") {
         t.Errorf("Expected code %d (OperationFailed) and 'Failed to retrieve created user' message, got code %d, message '%s'", proto.OperationFailed, resp.Code, resp.Message)
    }
}


func TestRegisterHandlerV2_TokenGenerationFails(t *testing.T) {
    setupServiceMocks()
    defer teardownServiceMocks()
    router := setupTestRouter()

    regDetails := RLReq{User: "newuser", Email: "new@example.com", Password: "password123", Code: "123456"}
    hashedPassword := func(s string) string { h := md5.New(); h.Write([]byte(s)); return hex.EncodeToString(h.Sum(nil)) }(regDetails.Password)
    createdUserID := uint(7)
    createdUserDAO := dao.User{ID: createdUserID, Name: regDetails.User, Email: regDetails.Email}

    mockWorkerGetRedis = func(key string) string { return regDetails.Code }
    mockServiceContainsUser = func(name, email string) bool { return false }
    mockServiceCreateUser = func(name, password, email, gender string, age int) uint { return createdUserID }
    mockServiceGetUserByIDWithCache = func(id int) dao.User { return createdUserDAO }
    mockServiceGenerateAuthTokens = func(user dao.User) (string, string, error) { return "", "", errors.New("token gen error") } // Token generation fails

    payloadBytes, _ := json.Marshal(regDetails)
    req, _ := http.NewRequest(http.MethodPost, "/user/register", bytes.NewBuffer(payloadBytes))
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    var resp proto.GenerateResp
    json.Unmarshal(rr.Body.Bytes(), &resp)
    if resp.Code != proto.TokenGenerationError {
        t.Errorf("Expected code %d (TokenGenerationError), got %d. Message: %s", proto.TokenGenerationError, resp.Code, resp.Message)
    }
}


// TODO: TestRegisterHandlerV2_UserExists (Covered by TestRegisterHandlerV2_UserExists)
// TODO: TestRegisterHandlerV2_InvalidCode (Covered by TestRegisterHandlerV2_InvalidCode)

func TestRefreshTokenHandler_Success(t *testing.T) {
	setupServiceMocks()
	defer teardownServiceMocks()
	router := setupTestRouter()

	mockNewAccessToken := "new_mock_access_token"
	mockOldRefreshToken := "old_mock_refresh_token"

	mockServiceValidateRefreshTokenAndCreateNewAccessToken = func(refreshTokenString string) (string, error) {
		if refreshTokenString == mockOldRefreshToken {
			return mockNewAccessToken, nil
		}
		return "", errors.New("unexpected refresh token in mock")
	}

	payload := RefreshTokenReq{RefreshToken: mockOldRefreshToken}
	payloadBytes, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, "/user/refresh_token", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v. Body: %s", status, http.StatusOK, rr.Body.String())
	}

	var resp map[string]interface{} // Assuming generic map for success response with data field
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Could not parse response JSON: %v", err)
	}

	if int(resp["code"].(float64)) != proto.SuccessCode {
		t.Errorf("Expected success code %d, got %v. Message: %v", proto.SuccessCode, resp["code"], resp["message"])
	}

	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Response data is not map[string]interface{}")
	}
	if accessToken, ok := data["access_token"].(string); !ok || accessToken != mockNewAccessToken {
		t.Errorf("Expected new access_token %s, got %v", mockNewAccessToken, data["access_token"])
	}
}

func TestRefreshTokenHandler_InvalidToken(t *testing.T) {
	setupServiceMocks()
	defer teardownServiceMocks()
	router := setupTestRouter()

	mockServiceValidateRefreshTokenAndCreateNewAccessToken = func(refreshTokenString string) (string, error) {
		return "", errors.New("invalid or expired token") // Simulate service layer error
	}

	payload := RefreshTokenReq{RefreshToken: "some_invalid_token_string"}
	payloadBytes, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, "/user/refresh_token", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Fatalf("handler returned wrong status code: got %v want %v. Body: %s", status, http.StatusUnauthorized, rr.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if int(resp["code"].(float64)) != proto.TokenInvalid {
		t.Errorf("Expected code %d (TokenInvalid), got %v. Message: %v", proto.TokenInvalid, resp["code"], resp["message"])
	}
}

func TestRefreshTokenHandler_MissingToken(t *testing.T) {
	setupServiceMocks() // Not strictly needed as service won't be called, but good for consistency
	defer teardownServiceMocks()
	router := setupTestRouter()

	// mockServiceValidateRefreshTokenAndCreateNewAccessToken is not set,
	// as the handler should validate presence before calling the service.

	payload := RefreshTokenReq{RefreshToken: ""} // Empty refresh token
	payloadBytes, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, "/user/refresh_token", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Fatalf("handler returned wrong status code: got %v want %v. Body: %s", status, http.StatusBadRequest, rr.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if int(resp["code"].(float64)) != proto.ParameterError {
		t.Errorf("Expected code %d (ParameterError) for missing token, got %v. Message: %v", proto.ParameterError, resp["code"], resp["message"])
	}
}

// TODO: TestGetUserInfo_Unauthorized (if middleware aspect can be simulated) - This depends on actual auth middleware tests.

// Mock for dao.FindUserByID2 used by GetUserInfo tests
var mockDAOFindUserByID2 func(id int) dao.User
var originalDAOFindUserByID2 func(id int) dao.User // To store the original

func TestGetUserInfo_Success_OwnInfo(t *testing.T) {
	setupServiceMocks() // Though GetUserInfo doesn't directly call services mocked here, it's good practice
	
	originalDAOFindUserByID2 = dao.FindUserByID2 // Store original
	dao.FindUserByID2 = func(id int) dao.User {   // Replace with mock
		if mockDAOFindUserByID2 != nil {
			return mockDAOFindUserByID2(id)
		}
		t.Fatalf("dao.FindUserByID2 mock not set for test")
		return dao.User{}
	}
	defer func() {
		dao.FindUserByID2 = originalDAOFindUserByID2 // Restore
		teardownServiceMocks()
	}()

	router := setupTestRouter() // Router without specific auth middleware for this direct call test

	mockUserID := uint(1)
	mockUser := dao.User{ID: mockUserID, Name: "selfuser", Email: "self@example.com", Password: "selfhashedpassword", Role: "user"}

	// Specific mock for this test case
	mockDAOFindUserByID2 = func(id int) dao.User {
		if uint(id) == mockUserID {
			return mockUser
		}
		return dao.User{}
	}
	
	// Simulate middleware setting context values
	router.Use(mockAuthMiddleware(mockUserID, mockUser.Name)) // Apply mock middleware for this route

	payload := GetUserInfoReq{ID: int(mockUserID)} // Requesting own info
	payloadBytes, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, "/user/info", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v. Body: %s", status, http.StatusOK, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Could not parse response JSON: %v", err)
	}

	if int(resp["code"].(float64)) != proto.SuccessCode {
		t.Errorf("Expected success code %d, got %v. Message: %v", proto.SuccessCode, resp["code"], resp["message"])
	}

	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Response data is not map[string]interface{}, got %T: %v", resp.Data, resp.Data)
	}

	if uint(data["ID"].(float64)) != mockUserID { // Note: `dao.User` fields are capitalized
		t.Errorf("Expected user ID %d, got %v", mockUserID, data["ID"])
	}
	if data["Name"].(string) != mockUser.Name {
		t.Errorf("Expected Name %s, got %v", mockUser.Name, data["Name"])
	}
	if data["Password"] != "" { // Password should be cleared by the handler
		t.Errorf("Expected Password to be empty, got '%v'", data["Password"])
	}
}


func TestGetUserInfo_AdminGetsOtherInfo(t *testing.T) {
	setupServiceMocks()
	originalDAOFindUserByID2 = dao.FindUserByID2
	dao.FindUserByID2 = func(id int) dao.User {
		if mockDAOFindUserByID2 != nil { return mockDAOFindUserByID2(id); }
		t.Fatalf("dao.FindUserByID2 mock not set"); return dao.User{}
	}
	defer func() { dao.FindUserByID2 = originalDAOFindUserByID2; teardownServiceMocks(); }()
	
	router := setupTestRouter()

	adminUserID := uint(10)
	adminUser := dao.User{ID: adminUserID, Name: "admin", Role: "admin"}
	targetUserID := uint(2)
	targetUser := dao.User{ID: targetUserID, Name: "target", Email: "target@example.com", Password: "targethashedpassword", Role: "user"}

	mockDAOFindUserByID2 = func(id int) dao.User {
		if uint(id) == adminUserID { return adminUser; }
		if uint(id) == targetUserID { return targetUser; }
		return dao.User{}
	}

	router.Use(mockAuthMiddleware(adminUserID, adminUser.Name))

	payload := GetUserInfoReq{ID: int(targetUserID)}
	payloadBytes, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, "/user/info", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v. Body: %s", status, http.StatusOK, rr.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if int(resp["code"].(float64)) != proto.SuccessCode {
		t.Errorf("Expected success code, got %v", resp["code"])
	}
	data, _ := resp["data"].(map[string]interface{})
	if uint(data["ID"].(float64)) != targetUserID {
		t.Errorf("Expected target user ID %d, got %v", targetUserID, data["ID"])
	}
	if data["Password"] != "" {
		t.Errorf("Expected target user Password to be empty, got '%v'", data["Password"])
	}
}

func TestGetUserInfo_NonAdminGetsOtherInfo_PermissionDenied(t *testing.T) {
    setupServiceMocks()
	originalDAOFindUserByID2 = dao.FindUserByID2
	dao.FindUserByID2 = func(id int) dao.User {
		if mockDAOFindUserByID2 != nil { return mockDAOFindUserByID2(id); }
		t.Fatalf("dao.FindUserByID2 mock not set"); return dao.User{}
	}
	defer func() { dao.FindUserByID2 = originalDAOFindUserByID2; teardownServiceMocks(); }()

    router := setupTestRouter()

    requestingUserID := uint(1)
    requestingUser := dao.User{ID: requestingUserID, Name: "requester", Role: "user"} // Non-admin
    targetUserID := uint(2) // Different user

    mockDAOFindUserByID2 = func(id int) dao.User {
        if uint(id) == requestingUserID { return requestingUser; }
        // Target user's details don't strictly matter here as permission should be denied first
        if uint(id) == targetUserID { return dao.User{ID: targetUserID, Name: "target", Password: "somepassword"}; }
        return dao.User{}
    }
    
	router.Use(mockAuthMiddleware(requestingUserID, requestingUser.Name))

    payload := GetUserInfoReq{ID: int(targetUserID)} // Attempting to get other user's info
    payloadBytes, _ := json.Marshal(payload)
    req, _ := http.NewRequest(http.MethodPost, "/user/info", bytes.NewBuffer(payloadBytes))
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    if status := rr.Code; status != http.StatusOK { // Handler returns 200 for this custom error
        t.Fatalf("handler returned wrong status code: got %v want %v. Body: %s", status, http.StatusOK, rr.Body.String())
    }
    var resp map[string]interface{}
    json.Unmarshal(rr.Body.Bytes(), &resp)
    if int(resp["code"].(float64)) != proto.PermissionDenied {
        t.Errorf("Expected code %d (PermissionDenied), got %v. Message: %v", proto.PermissionDenied, resp["code"], resp["message"])
    }
}

func TestGetUserInfo_UserNotFound(t *testing.T) {
    setupServiceMocks()
	originalDAOFindUserByID2 = dao.FindUserByID2
	dao.FindUserByID2 = func(id int) dao.User {
		if mockDAOFindUserByID2 != nil { return mockDAOFindUserByID2(id); }
		t.Fatalf("dao.FindUserByID2 mock not set"); return dao.User{}
	}
	defer func() { dao.FindUserByID2 = originalDAOFindUserByID2; teardownServiceMocks(); }()
    
    router := setupTestRouter()

    requestingUserID := uint(1)
    nonExistentUserID := 999

    mockDAOFindUserByID2 = func(id int) dao.User {
        if uint(id) == requestingUserID { return dao.User{ID: requestingUserID, Role: "user"}; } // For context
        if id == nonExistentUserID { return dao.User{}; } // User not found
        return dao.User{}
    }

	router.Use(mockAuthMiddleware(requestingUserID, "testuser"))

    payload := GetUserInfoReq{ID: nonExistentUserID}
    payloadBytes, _ := json.Marshal(payload)
    req, _ := http.NewRequest(http.MethodPost, "/user/info", bytes.NewBuffer(payloadBytes))
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)
    
    if status := rr.Code; status != http.StatusOK {
        t.Fatalf("handler returned wrong status code: got %v want %v. Body: %s", status, http.StatusOK, rr.Body.String())
    }
    var resp map[string]interface{}
    json.Unmarshal(rr.Body.Bytes(), &resp)
    if int(resp["code"].(float64)) != proto.SuccessCode { // Current handler returns success with empty user data
        t.Errorf("Expected SuccessCode even for not found user, got %v", resp["code"])
    }
    data, ok := resp["data"].(map[string]interface{})
    if !ok || uint(data["ID"].(float64)) != 0 { // Check if the returned user is indeed empty (ID 0)
        t.Errorf("Expected empty user data (ID 0) for not found user, got %v", data)
    }
}


// --- Helper for DAO mocking in GetUserInfo if needed ---
// var originalDAOFindUserByID2 func(id int) dao.User // Already handled with mockDAOFindUserByID2 pattern
// In setup:
// ...
// In teardown:
// ...

// For GetUserInfo, the current implementation gets user ID from c.Get("id").
// This is typically set by an auth middleware.
// Testing this directly requires either:
// 1. A mock middleware in the test router. (Used this approach)
// 2. Modifying GetUserInfo to take `id` as a parameter for easier testing (less ideal for handler signature).
// 3. Calling a lower-level service function if GetUserInfo primarily wraps one after ID extraction.

func mockAuthMiddleware(userID uint, username string) gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Set("id", float64(userID)) // Gin context stores float64 for numbers from JSON/JWT typically
        c.Set("username", username) // Also set username, as some handlers might use it
        c.Next()
    }
}
// Note: The actual route in SetUpUserGroup for /user/info is POST.
// The mockAuthMiddleware is applied globally to the router instance for these tests using router.Use().
// This means any route on that router instance will pass through this middleware.
// This is slightly different from applying it to a single route definition, but effective for testing this handler.

// Placeholder for dao.FindUserByID2 if it were a package-level var (it's not, it's a func - handled above)
// ...
