package repo

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	uuid "github.com/satori/go.uuid"
)

// Db represents a collections of databases. Users are stored
// in a map based on username as the key. Sessions are stored in a
// map based on cookie value as the key and username as the value.
type Db struct {
	Mu       sync.WaitGroup
	Users    map[string]User   // Mapping of Users
	Sessions map[string]string // Mapping of Sessions to username
	Log      *log.Logger
}

// User represents the user's information and password
type User struct {
	Username   string    `json:"username" xml:"username"`
	Password   []byte    `json:"password" xml:"password"`
	First      string    `json:"first" xml:"first"`
	Last       string    `json:"last" xml:"last"`
	TimeIn     time.Time `json:"time_in" xml:"time_in"`
	Attendance bool      `json:"attendance" xml:"attendnace"`
}

// XMLWrapper is required for parsing xml files
type XMLWrapper struct {
	XMLName xml.Name `xml:"users"`
	Users   []User   `json:"user" xml:"user"`
}

// Message represents different state messages
type Message struct {
	ErrorMessage    string
	ExportedMessage string
	LoadedMessage   string
}

// ViewData contains the data currently displayed to the user.
// The data is parsed into the templates.
type ViewData struct {
	User User
	Msg  Message
}

var (
	Tmpl           *template.Template
	viewData       ViewData
	errorMessage   string
	successMessage string
)

// NewDB returns an instance of a database of Db struct
func NewDB(logger *log.Logger) *Db {
	return &Db{
		Users:    make(map[string]User),
		Sessions: make(map[string]string),
		Log:      logger,
	}
}

// GetUser retrieves the current cookie and checks it against the
// database of sessions and users and returns the user. If no users is found
// a new session is created and set.
func (d *Db) GetUser(res http.ResponseWriter, req *http.Request) User {
	cookie, err := req.Cookie("sessionCookie")
	// Set new cookie when there is currently no cookie.
	if err != nil {
		id := uuid.NewV4()
		cookie = &http.Cookie{
			Name:  "sessionCookie",
			Value: id.String(),
		}
	}
	http.SetCookie(res, cookie)

	// Retrieve user if user already exist.
	var user User
	if username, ok := d.Sessions[cookie.Value]; ok {
		user = d.Users[username]
	}

	return user
}

// AlreadyLoggedIn checks for the current session to see if the user
// is already logged in and returns a boolean value.
func (d *Db) AlreadyLoggedIn(req *http.Request) bool {
	cookie, err := req.Cookie("sessionCookie")
	if err != nil {
		return false
	}
	username := d.Sessions[cookie.Value]
	_, ok := d.Users[username]
	return ok
}

// ExportAttendnace exports the current attendance base on the file type chosen
// by the user. Files are stored in the data subfolders based on type of file specified.
func (d *Db) ExportAttendance(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	res.Header().Set("Pragma", "no-cache")

	user := d.GetUser(res, req)
	if user.Username != "admin" {
		http.Redirect(res, req, "/", http.StatusSeeOther)
	}

	// Creating a slice to store users' data
	var usersData XMLWrapper

	for _, u := range d.Users {
		usersData.Users = append(usersData.Users, u)
	}

	// Declaration of variables and DateTime to track time of export.
	currentDateTime := time.Now().In(time.FixedZone("SGT", 8*60*60)).Truncate(time.Second)
	var exportData []byte
	var fileName string
	var err error
	fileType := req.URL.Query().Get("fileType")

	// Switch the appropriate export format based on the fileType parameter
	switch fileType {
	case "xml":
		exportData, err = xml.MarshalIndent(usersData, "", "  ")
		fileName = "data/xml/" + currentDateTime.Format("2006-01-02 15:04:05 -0700") + "attendance.xml"
	case "csv":
		exportData, err = d.exportCSV(usersData.Users)
		fileName = "data/csv/" + currentDateTime.Format("2006-01-02 15:04:05 -0700") + "attendance.csv"
	case "json":
		exportData, err = json.MarshalIndent(usersData.Users, "", "  ")
		fileName = "data/json/" + currentDateTime.Format("2006-01-02 15:04:05 -0700") + "attendance.json"
	default:
		d.Log.Println(err)
		http.Error(res, "Unsupported file type", http.StatusBadRequest)
		return
	}
	if err != nil {
		d.Log.Println(err)
		user := d.GetUser(res, req)
		viewData.User = user
		errorMessage = "Error marshaling " + fileType
		viewData.Msg.ExportedMessage = errorMessage
		err := Tmpl.ExecuteTemplate(res, "admin.gohtml", viewData)
		if err != nil {
			d.Log.Println(err)
		}
		return
	}

	// Write data to specified file type
	err = os.WriteFile(fileName, exportData, 0644)
	if err != nil {
		d.Log.Println(err)
		return
	}

	// Success response
	user = d.GetUser(res, req)
	viewData.User = user
	successMessage = fmt.Sprintf("Attendance exported to %s successfully", fileType)
	viewData.Msg.ExportedMessage = successMessage
	err = Tmpl.ExecuteTemplate(res, "admin.gohtml", viewData)
	if err != nil {
		d.Log.Println(err)
		http.Error(res, "Error loading page.", http.StatusNotFound)
		return
	}
}

// exportCSV parses the data passed to it, parsing the data into a
// slice of slices of users.
func (d *Db) exportCSV(data []User) ([]byte, error) {
	var csvData [][]string

	// Create a header row
	header := []string{"Username", "Password", "First", "Last", "TimeIn", "Attendance"}
	csvData = append(csvData, header)

	// Add data rows
	for _, user := range data {
		csvRow := []string{
			user.Username,
			string(user.Password),
			user.First,
			user.Last,
			user.TimeIn.Format("2006-01-02 15:04:05 -0700 MST"),
			strconv.FormatBool(user.Attendance),
		}
		csvData = append(csvData, csvRow)
	}

	// Write CSV data to a buffer
	var buff bytes.Buffer
	writer := csv.NewWriter(&buff)
	err := writer.WriteAll(csvData)
	if err != nil {
		d.Log.Println(err)
		return nil, err
	}

	return buff.Bytes(), nil
}

// ImportAttendance parses a file uploaded by the user and adds the data into
// the database.
func (d *Db) ImportAttendance(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	res.Header().Set("Pragma", "no-cache")

	user := d.GetUser(res, req)
	if user.Username != "admin" {
		http.Redirect(res, req, "/", http.StatusSeeOther)
	}

	var usersData XMLWrapper
	var importData []byte
	var err error

	// Get the file from file input form
	file, fileName, err := req.FormFile("file")
	if err != nil {
		d.Log.Println(err)
		return
	}
	defer file.Close()

	// Determine the file type based on the file name extension
	fileType := filepath.Ext(fileName.Filename)
	fileType = strings.TrimPrefix(fileType, ".")

	// Switch the appropriate export format based on the fileType parameter
	switch fileType {
	case "xml":
		importData, err = io.ReadAll(file)
		if err != nil {
			d.Log.Println(err)
			http.Error(res, "Error reading file", http.StatusInternalServerError)
			return
		}
		err = xml.Unmarshal(importData, &usersData)
	case "csv":
		importData, err = io.ReadAll(file)
		if err != nil {
			d.Log.Println(err)
			http.Error(res, "Error reading file", http.StatusInternalServerError)
			return
		}
		usersData.Users, err = d.importCSV(importData)
	case "json":
		importData, err = io.ReadAll(file)
		if err != nil {
			d.Log.Println(err)
			http.Error(res, "Error reading file", http.StatusInternalServerError)
			return
		}
		err = json.Unmarshal(importData, &usersData.Users)
	default:
		d.Log.Println(err)
		http.Error(res, "Unsupported file type", http.StatusBadRequest)
		return
	}
	if err != nil {
		d.Log.Println(err)
		myUser := d.GetUser(res, req)
		viewData := ViewData{User: myUser}
		errorMessage := "Error unmarshaling " + fileName.Filename
		viewData.Msg.LoadedMessage = errorMessage
		err := Tmpl.ExecuteTemplate(res, "admin.gohtml", viewData)
		if err != nil {
			d.Log.Println(err)
			http.Error(res, "Error loading page.", http.StatusNotFound)
		}
		return
	}

	// Clear the map and newly store users based on their username
	for key := range d.Users {
		delete(d.Users, key)
	}

	for _, user := range usersData.Users {
		d.Users[user.Username] = user
	}

	// Success response
	viewData := ViewData{}
	successMessage := fmt.Sprintf("Attendance imported from %s successfully", fileType)
	viewData.Msg.LoadedMessage = successMessage
	err = Tmpl.ExecuteTemplate(res, "admin.gohtml", viewData)
	if err != nil {
		d.Log.Println(err)
		http.Error(res, "Error loading page.", http.StatusNotFound)
		return
	}
}

// importCSV unmarshals the data read from the uploaded file and store the
// data in a slice of users.
func (d *Db) importCSV(data []byte) ([]User, error) {
	var users []User

	// Create a reader from the CSV data
	reader := csv.NewReader(bytes.NewReader(data))

	// Read all records from the CSV
	records, err := reader.ReadAll()
	if err != nil {
		d.Log.Println(err)
		return nil, err
	}

	// Check if there is at least one row excluding the header
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

		// Parse the Attendance field
		attendance, err := strconv.ParseBool(record[5])
		if err != nil {
			return nil, fmt.Errorf("error parsing Attendance field at line %d: %v", i+1, err)
		}

		// Create a User struct and append it to the users slice
		user := User{
			Username:   record[0],
			Password:   []byte(record[1]),
			First:      record[2],
			Last:       record[3],
			TimeIn:     timeIn,
			Attendance: attendance,
		}

		users = append(users, user)
	}

	return users, nil
}

// ViewAttendance displays the attendance list that is currently uploaded and in use.
func (d *Db) ViewAttendance(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	res.Header().Set("Pragma", "no-cache")

	Tmpl.ExecuteTemplate(res, "attendance.gohtml", d)
}
