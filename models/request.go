package models

// RegisterRequest represents the request body for user registration.
type RegisterRequest struct {
	// Define your request fields here
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}
