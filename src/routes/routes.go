package routes

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	repo "attendanceapp/src/repository"
	service "attendanceapp/src/service"
)

// Server represents the configuration of the server, including a
// reference to a AuthService and a database.
type Server struct {
	listenAddr string
	auth       *service.AuthService
	db         *repo.Db
}

// NewServer creates a instance of a server.
func NewServer(listenAddr string, as *service.AuthService, db *repo.Db) *Server {
	return &Server{
		listenAddr: listenAddr,
		auth:       as,
		db:         db,
	}
}

// RunServer starts HTTP server
func (s *Server) RunServer(cert, key string) {
	router := http.NewServeMux()

	// Load static files
	repo.Tmpl = template.Must(template.ParseGlob("src/static/*"))
	fileServer := http.FileServer(http.Dir("./src/static"))
	router.Handle("/src/static/", http.StripPrefix("/src/static/", fileServer))

	router.HandleFunc("/", s.auth.Login)
	router.HandleFunc("/signup", s.auth.Signup)
	router.HandleFunc("/logout", s.auth.Logout)
	router.HandleFunc("/admin/export", s.db.ExportAttendance)
	router.HandleFunc("/admin/import", s.db.ImportAttendance)
	router.HandleFunc("/admin/attendance", s.db.ViewAttendance)
	router.Handle("/favicon.ico", http.NotFoundHandler())

	fmt.Println("Server listening on port:", s.listenAddr)
	log.Fatal(http.ListenAndServeTLS(s.listenAddr, cert, key, router))
}
