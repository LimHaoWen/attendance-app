package main

import (
	repo "attendanceapp/src/repository"
	routes "attendanceapp/src/routes"
	sv "attendanceapp/src/service"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var errorLog *log.Logger

func main() {
	// Open and set file for logging
	logFile, err := os.OpenFile("src/infrastructure/app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	errorLog = log.New(logFile, "ERROR ", log.Ldate|log.Ltime|log.Lshortfile)
	if err != nil {
		errorLog.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Load environment variables
	err = godotenv.Load("src/infrastructure/.env")
	if err != nil {
		errorLog.Fatal(err)
	}

	// Db instance
	db := repo.NewDB(errorLog)

	// Service instance
	authService := sv.NewAuthService(db)

	// Server instance
	server := routes.NewServer("localhost:5332", authService, db)

	// Initializing of admin account
	bPassword, err := bcrypt.GenerateFromPassword([]byte(os.Getenv("ADMIN_PASSWORD")), bcrypt.MinCost)
	if err != nil {
		errorLog.Print(err)
	}
	db.Users["admin"] = repo.User{Username: string(os.Getenv("ADMIN_USERNAME")), Password: bPassword,
		First: "admin", Last: "admin", TimeIn: time.Time{}}

	// HTTPS
	cert := os.Getenv("CERT_FILE")
	key := os.Getenv("KEY_FILE")

	server.RunServer(cert, key)
}
