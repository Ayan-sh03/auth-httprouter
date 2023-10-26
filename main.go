package main

import (
	"auth/controllers"
	"auth/db"
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/julienschmidt/httprouter"
	_ "github.com/lib/pq"
)

func main() {
	// fmt.Printf("Hello")

	// var dbErr error
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading environment")
	}

	// dbname := os.Getenv("DB_NAME")
	// user := os.Getenv("DB_USER")
	// password := os.Getenv("DB_PASS")

	// Create the connection string using fmt.Sprintf
	connectionString := os.Getenv("DB_STRING")

	// Open the database connection
	Db, err := sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatal(err)
	}
	queries := db.New(Db)

	router := httprouter.New()
	basePath := "/api/v1/users"

	router.POST(basePath+"/register", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		controllers.RegisterUserController(w, r, queries)
	})
	router.POST(basePath+"/login", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		controllers.LoginController(w, r, queries)
	})

	router.POST(basePath+"/otp", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		controllers.CheckOtpController(w, r, queries)
	})

	log.Fatal(http.ListenAndServe(":8080", router))
}
