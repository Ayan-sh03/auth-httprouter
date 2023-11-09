package main

import (
	"auth/controllers"
	"auth/db"
	_ "auth/docs"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	httpSwagger "github.com/swaggo/http-swagger" // http-swagger middleware
)

// @title Authentication API
// @version 1.0
// @description This is an Authentication (Register, Verify, Login) server.

// @BasePath /api/v1/users
func main() {
	// Load environment variables
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading environment")
	}

	// Database configuration
	dbname := os.Getenv("DB_NAME")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASS")

	// Create the connection string using fmt.Sprintf
	connectionString := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", user, password, dbname)

	// Open the database connection
	Db, err := sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatal(err)
	}
	queries := db.New(Db)

	// Initialize the chi router
	router := chi.NewRouter()
	basePath := "/api/v1/users"

	// Middleware
	router.Use(middleware.Logger)

	// @summary Register a new user
	// @description Endpoint for user registration.
	// @tags users
	// @accept json
	// @produce json
	// @param body body RegisterRequest true "User registration details"
	// @success 200 {string} string "Successfully registered"
	router.Post(basePath+"/register", func(w http.ResponseWriter, r *http.Request) {
		controllers.RegisterUserController(w, r, queries)
	})

	// @summary User login
	// @description Endpoint for user login.
	// @tags users
	// @accept json
	// @produce json
	// @param body body LoginRequest true "User login details"
	// @success 200 {string} string "Login successful"
	router.Post(basePath+"/login", func(w http.ResponseWriter, r *http.Request) {
		controllers.LoginController(w, r, queries)
	})

	// @summary Check OTP
	// @description Endpoint for checking OTP.
	// @tags users
	// @accept json
	// @produce json
	// @param body body OtpCheckRequest true "OTP check details"
	// @success 200 {string} string "OTP verified"
	router.Post(basePath+"/otp", func(w http.ResponseWriter, r *http.Request) {
		controllers.CheckOtpController(w, r, queries)
	})

	// @summary Swagger UI
	// @description Endpoint for Swagger UI.
	// @produce html
	router.Get(basePath+"/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8080/api/v1/users/swagger/doc.json"), // The URL pointing to API definition
	))

	// CORS configuration
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
	})

	// Apply CORS middleware to the router
	handler := c.Handler(router)

	// Start the server
	log.Fatal(http.ListenAndServe(":8080", handler))
}
