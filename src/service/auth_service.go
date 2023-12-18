package service

import (
	repo "attendanceapp/src/repository"
	"net/http"
	"time"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

// AuthService holds a reference to a pointer to a database of Db struct.
type AuthService struct {
	db *repo.Db
}

// NewAuthService creates an instance of authservice with a database instance passed to it.
func NewAuthService(db *repo.Db) *AuthService {
	return &AuthService{db: db}
}

var errorMessage string
var viewData repo.ViewData

// Login checks if the user is already logged in based on session and signs in the user
// accordingly. If there is no current session for the current user, a new session is set.
func (as *AuthService) Login(res http.ResponseWriter, req *http.Request) {
	if as.db.AlreadyLoggedIn(req) {
		user := as.db.GetUser(res, req)
		if user.Username == "admin" {
			repo.Tmpl.ExecuteTemplate(res, "admin.gohtml", nil)
			return
		}
		viewData := repo.ViewData{
			User: user,
		}
		err := repo.Tmpl.ExecuteTemplate(res, "login_logout.gohtml", viewData)
		if err != nil {
			http.Error(res, "Error loading page.", http.StatusNotFound)
		}
		return
	}

	// Process form submission
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")

		// check if user exist with username
		user, ok := as.db.Users[username]
		viewData = repo.ViewData{
			User: user,
		}
		if !ok {
			errorMessage = "Username and/or password do not match"
			viewData.Msg.ErrorMessage = errorMessage
			err := repo.Tmpl.ExecuteTemplate(res, "login_logout.gohtml", viewData)
			if err != nil {
				http.Error(res, "Error loading page.", http.StatusNotFound)
			}
			return
		}
		// Matching of password entered
		err := bcrypt.CompareHashAndPassword(viewData.User.Password, []byte(password))
		if err != nil {
			errorMessage = "Username and/or password do not match"
			viewData.Msg.ErrorMessage = errorMessage
			err := repo.Tmpl.ExecuteTemplate(res, "login_logout.gohtml", viewData)
			if err != nil {
				http.Error(res, "Error loading page.", http.StatusNotFound)
			}
			return
		}
		// Create a session
		id := uuid.NewV4()
		timestamp := time.Now().In(time.FixedZone("SGT", 8*60*60)).Truncate(time.Second)
		// expirationTime := time.Now().Add(6 * time.Hour).In(time.FixedZone("SGT", 8*60*60)) //for expansion of the app
		cookie := &http.Cookie{
			Name:  "sessionCookie",
			Value: id.String(),
		}
		http.SetCookie(res, cookie)
		viewData.User.TimeIn = timestamp
		as.db.Sessions[cookie.Value] = username

		// Redirecting of the user either as an admin or regular user
		if username == "admin" {
			repo.Tmpl.ExecuteTemplate(res, "admin.gohtml", nil)
		} else {
			user.Attendance = true
			user.TimeIn = timestamp
			as.db.Users[username] = user

			err := repo.Tmpl.ExecuteTemplate(res, "login_logout.gohtml", viewData)
			if err != nil {
				http.Error(res, "Error loading page.", http.StatusNotFound)
			}
		}
		return
	}

	err := repo.Tmpl.ExecuteTemplate(res, "login_logout.gohtml", nil)
	if err != nil {
		http.Error(res, "Error loading page.", http.StatusNotFound)
	}
}

// Signup creates a new user and stores it in the database along with a
// session tagged to the user immediately.
func (as *AuthService) Signup(res http.ResponseWriter, req *http.Request) {
	if as.db.AlreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	viewData := repo.ViewData{}
	// process form submission
	if req.Method == http.MethodPost {
		// get form values
		username := req.FormValue("username")
		password := req.FormValue("password")
		firstname := req.FormValue("firstname")
		lastname := req.FormValue("lastname")
		if username != "" {
			// check if username exist/ taken
			if _, ok := as.db.Users[username]; ok {
				errorMessage = "Username already taken"
				viewData.Msg.ErrorMessage = errorMessage
				err := repo.Tmpl.ExecuteTemplate(res, "signup.gohtml", viewData)
				if err != nil {
					http.Error(res, "Error loading page.", http.StatusNotFound)
				}
				return
			}
			// create session
			id := uuid.NewV4()
			timestamp := time.Now().In(time.FixedZone("SGT", 8*60*60)).Truncate(time.Second)
			cookie := &http.Cookie{
				Name:  "sessionCookie",
				Value: id.String(),
			}
			http.SetCookie(res, cookie)
			as.db.Sessions[cookie.Value] = username

			bPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
			if err != nil {
				http.Error(res, "Internal server error", http.StatusInternalServerError)
				return
			}

			viewData.User = repo.User{Username: username, Password: bPassword,
				First: firstname, Last: lastname, TimeIn: timestamp, Attendance: true}
			as.db.Users[username] = viewData.User
		}
		// redirect to login page
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return

	}
	repo.Tmpl.ExecuteTemplate(res, "signup.gohtml", viewData)
}

// Logout checks for the current session and deletes it from the sessions database
// and redirects to the login page.
func (as *AuthService) Logout(res http.ResponseWriter, req *http.Request) {
	if !as.db.AlreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	cookie, _ := req.Cookie("sessionCookie")
	// delete the session
	delete(as.db.Sessions, cookie.Value)
	// remove the cookie
	cookie = &http.Cookie{
		Name:   "sessionCookie",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(res, cookie)

	http.Redirect(res, req, "/", http.StatusSeeOther)
}
