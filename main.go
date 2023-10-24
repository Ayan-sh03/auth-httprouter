package main

import (
	"auth/controllers"
	"auth/database"
	"auth/models"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/julienschmidt/httprouter"
	"gorm.io/gorm"
)

var Db *gorm.DB

func main() {
	// fmt.Printf("Hello")
	var dbErr error
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading environment")
	}

	config := &database.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		Password: os.Getenv("DB_PASS"),
		User:     os.Getenv("DB_USER"),
		DBName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("DB_SSL_MODE"),
	}
	Db, dbErr = database.NewConnection(config)

	if dbErr != nil {
		log.Fatal("could not load DB", dbErr)
	}
	err = models.MigrateUsers(Db)
	if err != nil {
		log.Fatal(err)
	}

	router := httprouter.New()
	basePath := "/api/v1/users"

	router.POST(basePath+"/register", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		controllers.RegisterUser(w, r, Db)
	})
	router.POST(basePath+"/login", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		controllers.LoginController(w, r, Db)
	})

	router.POST(basePath+"/otp", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		controllers.CheckOtpController(w, r, Db)
	})

	log.Fatal(http.ListenAndServe(":8080", router))
}
