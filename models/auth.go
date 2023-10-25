package models

import (
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Email      string `json:"email" gorm:"uniqueIndex"`
	Name       string `json:"name"`
	Password   string `json:"password"`
	IsVerified bool   `json:"is_verified" gorm:"default:false"`
	OTP        string `json:"otp"`
}

func (user *User) HashPassword(password string) error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return err
	}
	user.Password = string(bytes)
	return nil
}
func CheckPassword(providedPassword string, userPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(userPassword), []byte(providedPassword))
	if err != nil {
		return err
	}
	return nil
}
