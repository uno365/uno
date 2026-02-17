package domain

// RegisterRequest represents the request body for user registration.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterResponse represents the response body for successful registration.
type RegisterResponse struct {
	AccessToken string `json:"access_token"`
}

// LoginRequest represents the request body for user login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse represents the response body for successful login.
type LoginResponse struct {
	AccessToken string `json:"access_token"`
}

// RefreshResponse represents the response body for successful token refresh.
type RefreshResponse struct {
	AccessToken string `json:"access_token"`
}
