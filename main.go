package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string    `json:"username"`
	Password []byte    `json:"password"`
	First    string    `json:"first"`
	Last     string    `json:"last"`
	TimeIn   time.Time `json:"time_in"`
	Error    string    `json:"error"`
}

type Message struct {
	ExportedMessage string
	LoadedMessage   string
}

type AdminData struct {
	User User
	Data Message
}

var tmpl *template.Template
var errorMessage string
var successMessage string
var mapUsers = map[string]User{}
var mapSessions = map[string]string{}

func init() {
	// Loading of environment variables
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file:", err)
	}

	// Loading of static files
	tmpl = template.Must(template.ParseGlob("src/static/*"))
	http.Handle("/src/static/", http.StripPrefix("/src/static/", http.FileServer(http.Dir("./src/static"))))

	// Initializing of admin account
	bPassword, err := bcrypt.GenerateFromPassword([]byte(os.Getenv("ADMIN_PASSWORD")), bcrypt.MinCost)
	if err != nil {
		fmt.Println("error generating password:", err)
	}
	mapUsers["admin"] = User{string(os.Getenv("ADMIN_USERNAME")), bPassword, "admin", "admin", time.Time{}, ""}
}

func main() {
	http.HandleFunc("/", login)
	http.HandleFunc("/admin", admin)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/admin/export", exportAttendance)
	http.HandleFunc("/admin/import", importAttendance)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":5332", nil)
}

func login(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		myUser := getUser(res, req)
		err := tmpl.ExecuteTemplate(res, "login_logout.gohtml", myUser)
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
		myUser, ok := mapUsers[username]
		if !ok {
			errorMessage = "Username and/or password do not match"
			myUser.Error = errorMessage
			err := tmpl.ExecuteTemplate(res, "login_logout.gohtml", myUser)
			if err != nil {
				http.Error(res, "Error loading page.", http.StatusNotFound)
			}
			return
		}
		// Matching of password entered
		err := bcrypt.CompareHashAndPassword(myUser.Password, []byte(password))
		if err != nil {
			errorMessage = "Username and/or password do not match"
			myUser.Error = errorMessage
			err := tmpl.ExecuteTemplate(res, "login_logout.gohtml", myUser)
			if err != nil {
				http.Error(res, "Error loading page.", http.StatusNotFound)
			}
			return
		}
		// Create a session
		id := uuid.NewV4()
		timestamp := time.Now().In(time.FixedZone("SGT", 8*60*60))
		// expirationTime := time.Now().Add(6 * time.Hour).In(time.FixedZone("SGT", 8*60*60))
		cookie := &http.Cookie{
			Name:  "sessionCookie",
			Value: id.String(),
		}
		http.SetCookie(res, cookie)
		myUser.TimeIn = timestamp
		mapSessions[cookie.Value] = username
		if username == "admin" {
			http.Redirect(res, req, "/admin", http.StatusSeeOther)
		} else {
			http.Redirect(res, req, "/", http.StatusSeeOther)
		}
		return
	}

	myUser := getUser(res, req)
	err := tmpl.ExecuteTemplate(res, "login_logout.gohtml", myUser)
	if err != nil {
		http.Error(res, "Error loading page.", http.StatusNotFound)
	}
}

func admin(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	var data Message

	adminData := AdminData{
		User: myUser,
		Data: data,
	}
	// if !alreadyLoggedIn(req) {
	// 	http.Redirect(res, req, "/", http.StatusSeeOther)
	// 	return
	// }
	tmpl.ExecuteTemplate(res, "admin.gohtml", adminData)
}

func signup(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	var myUser User
	// process form submission
	if req.Method == http.MethodPost {
		// get form values
		username := req.FormValue("username")
		password := req.FormValue("password")
		firstname := req.FormValue("firstname")
		lastname := req.FormValue("lastname")
		if username != "" {
			// check if username exist/ taken
			if _, ok := mapUsers[username]; ok {
				errorMessage := "Username already taken"
				myUser.Error = errorMessage
				err := tmpl.ExecuteTemplate(res, "signup.gohtml", myUser)
				if err != nil {
					http.Error(res, "Error loading page.", http.StatusNotFound)
				}
				return
			}
			// create session
			id := uuid.NewV4()
			timestamp := time.Now().In(time.FixedZone("SGT", 8*60*60))
			cookie := &http.Cookie{
				Name:  "sessionCookie",
				Value: id.String(),
			}
			http.SetCookie(res, cookie)
			mapSessions[cookie.Value] = username

			bPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
			if err != nil {
				http.Error(res, "Internal server error", http.StatusInternalServerError)
				return
			}

			myUser = User{username, bPassword, firstname, lastname, timestamp, ""}
			mapUsers[username] = myUser
		}
		// redirect to login page
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return

	}
	tmpl.ExecuteTemplate(res, "signup.gohtml", myUser)
}

func logout(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	cookie, _ := req.Cookie("sessionCookie")
	// delete the session
	delete(mapSessions, cookie.Value)
	// remove the cookie
	cookie = &http.Cookie{
		Name:   "sessionCookie",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(res, cookie)

	http.Redirect(res, req, "/", http.StatusSeeOther)
}

func getUser(res http.ResponseWriter, req *http.Request) User {
	// get current session cookie
	cookie, err := req.Cookie("sessionCookie")
	if err != nil {
		id := uuid.NewV4()
		cookie = &http.Cookie{
			Name:  "sessionCookie",
			Value: id.String(),
		}
	}
	http.SetCookie(res, cookie)

	// if the user exists already, get user
	var myUser User
	if username, ok := mapSessions[cookie.Value]; ok {
		myUser = mapUsers[username]
	}

	return myUser
}

func alreadyLoggedIn(req *http.Request) bool {
	cookie, err := req.Cookie("sessionCookie")
	if err != nil {
		return false
	}
	username := mapSessions[cookie.Value]
	_, ok := mapUsers[username]
	return ok
}

func exportAttendance(res http.ResponseWriter, req *http.Request) {
	// Create a slice to store attendance data
	var attendanceData []map[string]interface{}

	// Iterate over the mapUsers to collect attendance data
	for _, u := range mapUsers {
		userAttendance := map[string]interface{}{
			"Username": u.Username,
			"Password": u.Password,
			"First":    u.First,
			"Last":     u.Last,
			"TimeIn":   u.TimeIn.Format(time.RFC3339),
			"Error":    u.Error,
		}
		attendanceData = append(attendanceData, userAttendance)
	}

	// Convert the attendanceData slice to JSON
	jsonData, err := json.MarshalIndent(attendanceData, "", "  ")
	if err != nil {
		http.Error(res, "Error marshaling JSON", http.StatusInternalServerError)
		return
	}

	// Write the JSON data to a file (change the filename as needed)
	err = os.WriteFile("data/attendance.json", jsonData, 0644)
	if err != nil {
		http.Error(res, "Error writing JSON file", http.StatusInternalServerError)
		return
	}

	// Success response
	adminData := AdminData{}
	successMessage = "Attendance data exported successfully"
	adminData.Data.ExportedMessage = successMessage
	err = tmpl.ExecuteTemplate(res, "admin.gohtml", adminData)
	if err != nil {
		http.Error(res, "Error loading page.", http.StatusNotFound)
		return
	}
}

func importAttendance(res http.ResponseWriter, req *http.Request) {
	// Read the JSON data from the file (change the filename as needed)
	jsonData, err := os.ReadFile("attendance.json")
	if err != nil {
		http.Error(res, "Error reading JSON file", http.StatusInternalServerError)
		return
	}

	// Create a slice to store imported attendance data
	var importedAttendance []User

	// Unmarshal the JSON data into the importedAttendance slice
	err = json.Unmarshal(jsonData, &importedAttendance)
	if err != nil {
		http.Error(res, "Error unmarshaling JSON", http.StatusInternalServerError)
		return
	}

	// Update the mapUsers with the imported attendance data
	for _, u := range importedAttendance {
		mapUsers[u.Username] = u
		fmt.Println(mapUsers[u.Username])
	}

	// Send a success response
	adminData := AdminData{}
	successMessage = "Attendance data loaded successfully"
	adminData.Data.LoadedMessage = successMessage
	err = tmpl.ExecuteTemplate(res, "admin.gohtml", adminData)
	if err != nil {
		http.Error(res, "Error loading page.", http.StatusNotFound)
		return
	}
}
