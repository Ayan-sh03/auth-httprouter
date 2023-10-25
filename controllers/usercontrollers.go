package controllers

import (
	"auth/authorization"
	"auth/db"
	"auth/models"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
)

type TokenRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type OTPRequest struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
}

func generateOTP() (string, error) {
	// Define the range for the OTP (5 digits)
	min := int64(10000)
	max := int64(99999)

	// Generate a cryptographically secure random number within the defined range

	randomInt, err := rand.Int(rand.Reader, new(big.Int).Sub(big.NewInt(max), big.NewInt(min)))
	if err != nil {
		return "", err
	}

	// Add the minimum value to ensure a 5-digit OTP
	otpValue := randomInt.Int64() + min

	// Format the OTP as a string with leading zeros
	otp := fmt.Sprintf("%05d", otpValue)

	return (otp), nil
}

func LoginController(w http.ResponseWriter, r *http.Request, q *db.Queries) {
	var request TokenRequest
	var user db.User
	decoder := json.NewDecoder(r.Body)

	if err := decoder.Decode(&request); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	var err error
	user, err = q.GetUserByEmail(context.Background(), request.Email) // Use the generated function
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Println(user)

	credentialsError := models.CheckPassword(request.Password, user.Password)
	if credentialsError != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid Credentials")
		return
	}

	tokenString, err := authorization.GenerateJWT(user.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"token": tokenString})
}

func CheckOtpController(w http.ResponseWriter, r *http.Request, q *db.Queries) {
	var otpRequest OTPRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&otpRequest); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	user, err := q.GetUserByEmail(context.Background(), otpRequest.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	userotp := user.Otp
	log.Println(userotp.String)
	if otpRequest.OTP != (userotp.String) {
		respondWithError(w, http.StatusUnauthorized, "Invalid OTP")
		return
	}

	tokenString, err := authorization.GenerateJWT(user.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	go func() {
		if err := q.UpdateUserByEmail(context.Background(), otpRequest.Email); err != nil {
			respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}()

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "OTP Verified", "token": tokenString})
}

func respondWithError(w http.ResponseWriter, status int, message string) {
	response := map[string]string{"error": message}
	respondWithJSON(w, status, response)
}

func respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Println("Error encoding JSON response:", err)
	}
}

func RegisterUserController(w http.ResponseWriter, r *http.Request, queries *db.Queries) {
	var user models.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&user); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if user.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is missing")
		return
	}

	_, err := mail.ParseAddress(user.Email)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Please provide a valid email Adress")
		return
	}

	if user.Name == "" {
		respondWithError(w, http.StatusBadRequest, "Name is missing")
		return
	}
	if user.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is missing")
		return
	}

	if err := user.HashPassword(user.Password); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	otp, err := generateOTP()

	user.OTP = otp

	if err != nil {
		log.Fatal("error in generating OTP", err)
	}
	var userError error
	_, userError = queries.CreateUser(context.Background(), db.CreateUserParams{
		Email:    user.Email,
		Name:     user.Name,
		Password: user.Password,
		Otp:      sql.NullString{String: user.OTP, Valid: true},
	})

	if userError != nil {
		// Log the error for debugging
		log.Println("Error creating user:", userError)

		if strings.Contains(userError.Error(), "unique constraint") {
			respondWithError(w, http.StatusConflict, "Email already in use")
		} else {
			respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	//!sending otp
	auth := smtp.PlainAuth("", os.Getenv("EMAIL"), os.Getenv("PASSWORD"), "smtp.gmail.com")

	to := []string{user.Email}

	message := []byte("To: " + user.Email + "\r\n" +
		"Subject: OTP for Registration\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=\"utf-8\"\r\n\r\n" +
		"<html><body>" +
		"<h1>Your OTP for registration is <strong>" + otp + "</strong></h1>" +
		"</body></html>")

	go func() {
		err := smtp.SendMail("smtp.gmail.com:587", auth, os.Getenv("EMAIL"), to, message)
		if err != nil {
			log.Println("Error in sending OTP:", err)
		}
	}()
	//!

	// log.Println(record)

	respondWithJSON(w, http.StatusCreated, map[string]string{"message": "User Registered Successfully, OTP sent to your email"})

}
