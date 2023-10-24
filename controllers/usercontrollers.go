package controllers

import (
	"auth/authorization"
	"auth/models"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/smtp"
	"os"

	"gorm.io/gorm"
)

var cache = make(map[string]string)

type TokenRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type OTPRequest struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
}

func RegisterUser(w http.ResponseWriter, r *http.Request, Db *gorm.DB) {
	var user models.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&user); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if err := user.HashPassword(user.Password); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	//!sending otp
	auth := smtp.PlainAuth("", os.Getenv("EMAIL"), os.Getenv("PASSWORD"), "smtp.gmail.com")

	to := []string{user.Email}
	otp, err := generateOTP()
	cache[user.Email] = otp
	user.OTP = otp

	if err != nil {
		log.Fatal("error in generating OTP", err)
	}
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
	record := Db.Create(&user)
	if record.Error != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	respondWithJSON(w, http.StatusCreated, map[string]string{"message": "User Registered Successfully, OTP sent to your email"})
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

func LoginController(w http.ResponseWriter, r *http.Request, Db *gorm.DB) {
	var request TokenRequest
	var user models.User
	decoder := json.NewDecoder(r.Body)

	if err := decoder.Decode(&request); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	record := Db.Where("email=?", request.Email).First(&user)
	if record.Error != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	credentialsError := user.CheckPassword(request.Password)
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

func CheckOtpController(w http.ResponseWriter, r *http.Request, Db *gorm.DB) {
	var otpRequest OTPRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&otpRequest); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	user, err := findUserByEmail(Db, otpRequest.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	if otpRequest.OTP != user.OTP {
		respondWithError(w, http.StatusUnauthorized, "Invalid OTP")
		return
	}

	if err := updateUserVerificationStatus(Db, otpRequest.Email); err != nil {
		log.Println("Error updating user verification status:", err)
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "OTP Verified"})
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

func findUserByEmail(Db *gorm.DB, email string) (models.User, error) {
	var user models.User
	if err := Db.Where("email=?", email).First(&user).Error; err != nil {
		return user, err
	}
	return user, nil
}

func updateUserVerificationStatus(Db *gorm.DB, email string) error {
	return Db.Model(&models.User{}).Where("email = ?", email).Updates(models.User{IsVerified: true}).Error
}
