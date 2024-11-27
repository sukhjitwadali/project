package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var templates = template.Must(template.ParseGlob("templates/*.html"))

func initDB() {
	var err error
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	dsn := dbUser + ":" + dbPassword + "@tcp(" + dbHost + ")/" + dbName
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Database is not reachable: %v", err)
	}
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	templates.ExecuteTemplate(w, tmpl+".html", data)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing password: %v", err)
			http.Error(w, "Unable to create user", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", username, email, hashedPassword)
		if err != nil {
			log.Printf("Error inserting user: %v", err)
			http.Error(w, "Unable to create user", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "signup", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var dbPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&dbPassword)
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Compare the hashed password
		err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		http.Redirect(w, r, "/success", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "login", nil)
}

func successHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "success", nil)
}

func main() {
	initDB()
	defer db.Close()

	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/success", successHandler)
	// Add to main function for routing
	http.HandleFunc("/forgot_password", forgotPasswordHandler)
	http.HandleFunc("/reset", setNewPasswordHandler)

	log.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}

// Reset password handler
func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")

		// Check if the email exists in the database
		var username string
		err := db.QueryRow("SELECT username FROM users WHERE email = ?", email).Scan(&username)
		if err != nil {
			http.Error(w, "Email not found", http.StatusNotFound)
			return
		}

		// Simulate sending a password reset link to the user's email
		// In a real scenario, you would send a real email here.
		log.Printf("Password reset link sent to: %s", email)

		// Redirect to the password reset form
		http.Redirect(w, r, "/reset", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "forgot_password", nil)
}

// Form to enter the new password
func setNewPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		newPassword := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		if newPassword != confirmPassword {
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			return
		}

		// Update the password in the database
		// Assuming we get the user ID via session or token, here we directly update for simplicity
		_, err := db.Exec("UPDATE users SET password = ? WHERE username = ?", newPassword, "user") // Example: Replace with actual username from session or token
		if err != nil {
			http.Error(w, "Unable to update password", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "reset_password", nil)
}

// Forgot password handler
func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")

		// Check if the email exists in the database
		var username string
		err := db.QueryRow("SELECT username FROM users WHERE email = ?", email).Scan(&username)
		if err != nil {
			http.Error(w, "Email not found", http.StatusNotFound)
			return
		}

		// Simulate sending a password reset link to the user's email
		// In a real scenario, you would send a real email here.
		log.Printf("Password reset link sent to: %s", email)

		// Redirect to the password reset form
		http.Redirect(w, r, "/reset", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "forgot_password", nil)
}
