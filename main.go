package main

import (
	repo "attendanceapp/src/repository"
	routes "attendanceapp/src/routes"
	sv "attendanceapp/src/service"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	// Load environment variables
	err := godotenv.Load("src/infrastructure/.env")
	if err != nil {
		fmt.Println("Error loading .env file:", err)
	}

	// Open and set file for logging
	logFile, err := os.OpenFile("src/infrastructure/app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("Error opening log file:", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Load static files
	repo.Tmpl = template.Must(template.ParseGlob("src/static/*"))
	http.Handle("/src/static/", http.StripPrefix("/src/static/", http.FileServer(http.Dir("./src/static"))))
}

func main() {
	db := repo.NewDB()

	authService := sv.NewAuthService(db)

	server := routes.NewServer("localhost:5332", authService, db)

	// Initializing of admin account
	bPassword, err := bcrypt.GenerateFromPassword([]byte(os.Getenv("ADMIN_PASSWORD")), bcrypt.MinCost)
	if err != nil {
		fmt.Println("error generating password:", err)
	}
	db.Users["admin"] = repo.User{Username: string(os.Getenv("ADMIN_USERNAME")), Password: bPassword,
		First: "admin", Last: "admin", TimeIn: time.Time{}}

	server.RunServer()
}
