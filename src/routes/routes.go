package routes

import (
	"log"
	"net/http"

	repo "attendanceapp/src/repository"
	"attendanceapp/src/service"
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
func (s *Server) RunServer() {
	http.HandleFunc("/", s.auth.Login)
	http.HandleFunc("/signup", s.auth.Signup)
	http.HandleFunc("/logout", s.auth.Logout)
	http.HandleFunc("/admin/export", s.db.ExportAttendance)
	http.HandleFunc("/admin/import", s.db.ImportAttendance)
	http.HandleFunc("/admin/attendance", s.db.ViewAttendance)
	http.Handle("/favicon.ico", http.NotFoundHandler())

	log.Fatal(http.ListenAndServe(s.listenAddr, nil))
}
