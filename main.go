package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string    `json:"username" xml:"username"`
	Password []byte    `json:"password" xml:"password"`
	First    string    `json:"first" xml:"first"`
	Last     string    `json:"last" xml:"last"`
	TimeIn   time.Time `json:"time_in" xml:"time_in"`
	Error    string    `json:"error" xml:"error"`
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
	//http.HandleFunc("/admin", admin)
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
		timestamp := time.Now().In(time.FixedZone("SGT", 8*60*60)).Truncate(time.Second)
		// expirationTime := time.Now().Add(6 * time.Hour).In(time.FixedZone("SGT", 8*60*60))
		cookie := &http.Cookie{
			Name:  "sessionCookie",
			Value: id.String(),
		}
		http.SetCookie(res, cookie)
		myUser.TimeIn = timestamp
		mapSessions[cookie.Value] = username
		if username == "admin" {
			//http.Redirect(res, req, "/admin", http.StatusSeeOther)
			myUser := getUser(res, req)
			var data Message

			adminData := AdminData{
				User: myUser,
				Data: data,
			}
			tmpl.ExecuteTemplate(res, "admin.gohtml", adminData)
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

// func admin(res http.ResponseWriter, req *http.Request) {

// 	// if !alreadyLoggedIn(req) {
// 	// 	http.Redirect(res, req, "/", http.StatusSeeOther)
// 	// 	return
// 	// }

// }

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
			timestamp := time.Now().In(time.FixedZone("SGT", 8*60*60)).Truncate(time.Second)
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
	// Create a slice to store users' data
	var usersData Users

	for _, u := range mapUsers {
		usersData.Users = append(usersData.Users, u)
	}

	adminData := AdminData{}
	currentDateTime := time.Now().In(time.FixedZone("SGT", 8*60*60)).Truncate(time.Second)
	var exportData []byte
	var fileName string
	var err error
	fileType := req.URL.Query().Get("fileType")

	// Choose the appropriate export format based on the fileType parameter
	switch fileType {
	case "xml":
		exportData, err = xml.MarshalIndent(usersData, "", "  ")
		fileName = "data/" + currentDateTime.Format("2006-01-02 15:04:05 -0700") + "attendance.xml"
	case "csv":
		exportData, err = exportCSV(usersData.Users)
		fileName = "data/" + currentDateTime.Format("2006-01-02 15:04:05 -0700") + "attendance.csv"
	case "json":
		exportData, err = json.MarshalIndent(usersData.Users, "", "  ")
		fileName = "data/" + currentDateTime.Format("2006-01-02 15:04:05 -0700") + "attendance.json"
	default:
		http.Error(res, "Unsupported file type", http.StatusBadRequest)
		return
	}

	if err != nil {
		myUser := getUser(res, req)
		adminData.User = myUser
		errorMessage := "Error marshaling " + fileType
		adminData.User.Error = errorMessage
		err := tmpl.ExecuteTemplate(res, "admin.gohtml", adminData)
		if err != nil {
			http.Error(res, "Error loading page.", http.StatusNotFound)
		}
		return
	}

	// Write data to specified file type
	err = os.WriteFile(fileName, exportData, 0644)
	if err != nil {
		http.Error(res, "Error writing "+fileType+" file", http.StatusInternalServerError)
		return
	}

	// Success response
	adminData = AdminData{}
	successMessage = fmt.Sprintf("Attendance exported to %s successfully", fileType)
	adminData.Data.ExportedMessage = successMessage
	err = tmpl.ExecuteTemplate(res, "admin.gohtml", adminData)
	if err != nil {
		http.Error(res, "Error loading page.", http.StatusNotFound)
		return
	}
}

func exportCSV(data []User) ([]byte, error) {
	// Create a slice of slice where data is stored
	var csvData [][]string

	// Create a header row
	header := []string{"Username", "Password", "First", "Last", "TimeIn", "Error"}
	csvData = append(csvData, header)

	// Add data rows
	for _, user := range data {
		csvRow := []string{
			user.Username,
			string(user.Password),
			user.First,
			user.Last,
			user.TimeIn.Format("2006-01-02 15:04:05 -0700 MST"),
			user.Error,
		}
		csvData = append(csvData, csvRow)
	}

	// Write CSV data to a buffer
	var buff bytes.Buffer
	writer := csv.NewWriter(&buff)
	err := writer.WriteAll(csvData)
	if err != nil {
		return nil, err
	}

	return buff.Bytes(), nil
}

type Users struct {
	XMLName xml.Name `xml:"users"`
	Users   []User   `json:"user" xml:"user"`
}

func importAttendance(res http.ResponseWriter, req *http.Request) {
	var usersData Users
	var importData []byte
	var err error

	// Get the file from file input form
	file, fileName, err := req.FormFile("file")
	if err != nil {
		http.Error(res, "Error parsing file from the request", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Determine the file type based on the file name extension
	fileType := filepath.Ext(fileName.Filename)
	fileType = strings.TrimPrefix(fileType, ".")

	switch fileType {
	case "xml":
		importData, err = io.ReadAll(file)
		if err != nil {
			http.Error(res, "Error reading file", http.StatusInternalServerError)
			return
		}
		// modifiedData := []byte("<Users>" + string(importData) + "</Users>")
		err = xml.Unmarshal(importData, &usersData)
		if err != nil {
			myUser := getUser(res, req)
			adminData := AdminData{User: myUser}
			errorMessage := "Error unmarshaling " + fileType
			adminData.User.Error = errorMessage
			err := tmpl.ExecuteTemplate(res, "admin.gohtml", adminData)
			if err != nil {
				http.Error(res, "Error loading page.", http.StatusNotFound)
			}
			return
		}
	case "csv":
		importData, err = io.ReadAll(file)
		if err != nil {
			http.Error(res, "Error reading file", http.StatusInternalServerError)
			return
		}
		usersData.Users, err = importCSV(importData)
		if err != nil {
			myUser := getUser(res, req)
			adminData := AdminData{User: myUser}
			errorMessage := "Error unmarshaling " + fileType
			adminData.User.Error = errorMessage
			err := tmpl.ExecuteTemplate(res, "admin.gohtml", adminData)
			if err != nil {
				http.Error(res, "Error loading page.", http.StatusNotFound)
			}
			return
		}
	case "json":
		importData, err = io.ReadAll(file)
		if err != nil {
			http.Error(res, "Error reading file", http.StatusInternalServerError)
			return
		}
		err = json.Unmarshal(importData, &usersData.Users)
		if err != nil {
			myUser := getUser(res, req)
			adminData := AdminData{User: myUser}
			errorMessage := "Error unmarshaling " + fileType
			adminData.User.Error = errorMessage
			err := tmpl.ExecuteTemplate(res, "admin.gohtml", adminData)
			if err != nil {
				http.Error(res, "Error loading page.", http.StatusNotFound)
			}
			return
		}
	default:
		http.Error(res, "Unsupported file type", http.StatusBadRequest)
		return
	}

	fmt.Println(usersData)
	// Create a map to store users based on their username
	for _, user := range usersData.Users {
		mapUsers[user.Username] = user
	}

	// Success response
	adminData := AdminData{}
	successMessage := fmt.Sprintf("Attendance imported from %s successfully", fileType)
	adminData.Data.LoadedMessage = successMessage
	err = tmpl.ExecuteTemplate(res, "admin.gohtml", adminData)
	if err != nil {
		http.Error(res, "Error loading page.", http.StatusNotFound)
		return
	}
}

func importCSV(data []byte) ([]User, error) {
	var users []User

	// Create a reader from the CSV data
	reader := csv.NewReader(bytes.NewReader(data))

	// Read all records from the CSV
	records, err := reader.ReadAll()
	fmt.Println(records)
	if err != nil {
		return nil, err
	}

	// Check if there is at least one row (excluding the header)
	if len(records) < 2 {
		return nil, errors.New("CSV file does not contain data rows")
	}

	// Iterate over the records and convert them to User structs
	for i := 1; i < len(records); i++ {
		record := records[i]

		// Ensure the record has the expected number of fields
		if len(record) != 6 {
			return nil, fmt.Errorf("CSV record at line %d has an incorrect number of fields", i+1)
		}

		// Parse the TimeIn field
		timeIn, err := time.Parse("2006-01-02 15:04:05 -0700 MST", record[4])
		if err != nil {
			return nil, fmt.Errorf("error parsing TimeIn field at line %d: %v", i+1, err)
		}

		// Create a User struct and append it to the users slice
		user := User{
			Username: record[0],
			Password: []byte(record[1]),
			First:    record[2],
			Last:     record[3],
			TimeIn:   timeIn,
			Error:    record[5],
		}

		users = append(users, user)
	}

	return users, nil
}
