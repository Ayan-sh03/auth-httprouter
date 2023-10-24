package models

import (
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email      string `json:"email" gorm:"uniqueIndex"`
	Name       string `json:"name"`
	Password   string `json:"password"`
	IsVerified bool   `json:"is_verified" gorm:"default:false"`
	OTP        string `json:"otp"`
}

func MigrateUsers(db *gorm.DB) error {
	err := db.AutoMigrate(&User{})
	return err
}

func (user *User) HashPassword(password string) error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return err
	}
	user.Password = string(bytes)
	return nil
}
func (user *User) CheckPassword(providedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(providedPassword))
	if err != nil {
		return err
	}
	return nil
}
