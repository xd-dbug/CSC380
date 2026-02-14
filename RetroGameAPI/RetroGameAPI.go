package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/segmentio/kafka-go"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var jwtSecret []byte
var kafkaWriter *kafka.Writer

type game struct {
	ID        int     `json:"id"`
	Title     string  `json:"title" binding:"required"`
	Platform  string  `json:"platform" binding:"required"`
	Year      int     `json:"year"`
	Condition string  `json:"condition"`
	OwnerID   int     `json:"ownerId"`
	MadeBy    company `json:"madeBy" binding:"required"`
}

type gameUpdate struct {
	ID        int     `json:"id"`
	Title     string  `json:"title"`
	Platform  string  `json:"platform"`
	Year      int     `json:"year"`
	Condition string  `json:"condition"`
	MadeBy    company `json:"madeBy"`
}

type user struct {
	ID       int    `json:"id"`
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
	FullName string `json:"fullName"`
}

type userUpdate struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"fullName"`
}

type company struct {
	ID          int    `json:"id"`
	CompanyName string `json:"companyName" binding:"required"`
	YearFounded int    `json:"yearFounded" binding:"required"`
	Location    string `json:"location" binding:"required"`
}

type tradeOffer struct {
	ID              int    `json:"id"`
	CreatedByUserID int    `json:"createdByUserId"`
	TargetGameID    int    `json:"targetGameId"`
	OfferedGameID   int    `json:"offeredGameId"`
	Status          string `json:"status"`
	CreatedAt       string `json:"createdAt"`
	UpdatedAt       string `json:"updatedAt"`
}

type tradeOfferRequest struct {
	TargetGameID  int `json:"targetGameId" binding:"required"`
	OfferedGameID int `json:"offeredGameId" binding:"required"`
}

type tradeOfferResponse struct {
	ID              int    `json:"id"`
	CreatedByUserID int    `json:"createdByUserId"`
	CreatedByUser   user   `json:"createdByUser"`
	TargetGameID    int    `json:"targetGameId"`
	TargetGame      game   `json:"targetGame"`
	OfferedGameID   int    `json:"offeredGameId"`
	OfferedGame     game   `json:"offeredGame"`
	Status          string `json:"status"`
	CreatedAt       string `json:"createdAt"`
	UpdatedAt       string `json:"updatedAt"`
}

type statusUpdateRequest struct {
	Status string `json:"status" binding:"required"`
}

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type loginResponse struct {
	Token   string `json:"token"`
	UserID  int    `json:"userId"`
	Message string `json:"message"`
}

type registerRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
	FullName string `json:"fullName"`
	Password string `json:"password" binding:"required"`
}

type CustomClaims struct {
	UserID   int    `json:"userId"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type Event string

const (
	OfferCreated  Event = "OfferCreated"
	OfferAccepted Event = "OfferAccepted"
	OfferRejected Event = "OfferRejected"
)

type EmailNotification struct {
	EventType  Event         `json:"eventType"`
	Recipient1 mail.Address  `json:"recipient1"`
	Recipient2 *mail.Address `json:"recipient2"`
	Subject    string        `json:"subject"`
	Body       string        `json:"body"`
}

func init() {
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")
	jwtSecretStr := os.Getenv("JWT_SECRET")
	kafkaBroker := os.Getenv("KAFKA_BROKER")

	if dbUser == "" {
		dbUser = "root"
	}
	if dbPassword == "" {
		dbPassword = "password"
	}
	if dbHost == "" {
		dbHost = "localhost"
	}
	if dbPort == "" {
		dbPort = "3306"
	}
	if dbName == "" {
		dbName = "RetroGameDB"
	}
	if jwtSecretStr == "" {
		jwtSecretStr = "secret"
	}
	if kafkaBroker == "" {
		kafkaBroker = "broker:19092"
	}

	kafkaWriter = &kafka.Writer{
		Addr:     kafka.TCP(kafkaBroker),
		Topic:    "notificationEvents",
		Balancer: &kafka.LeastBytes{},
	}
	jwtSecret = []byte(jwtSecretStr)

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Println("Connected to MySQL database successfully")
}

func publishEmailNotification(notification EmailNotification) error {
	err := kafkaWriter.WriteMessages(context.Background(),
		kafka.Message{
			Key:   []byte("email"),
			Value: []byte(notification),
		})
	if err != nil {
		log.Panic("failed to write messages: ", err)
	}

	if err := kafkaWriter.Close(); err != nil {
		log.Panic("failed to close writer: ", err)
	}
	return nil
}

// JWT AUTHENTICATION MIDDLEWARE
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Parse and validate token
		token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Verify the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: " + err.Error()})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*CustomClaims)
		if !ok || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Check if token has expired
		if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
			c.Abort()
			return
		}

		// Set user info in context
		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Next()
	}
}

// AUTHENTICATION ENDPOINTS

// Register a new user
func register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if username already exists
	row := db.QueryRow("SELECT UserID FROM User WHERE Username = ?", req.Username)
	var existingID int
	err := row.Scan(&existingID)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	// Hash password using bcrypt
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	// Insert new user
	result, err := db.Exec(
		"INSERT INTO User (Username, Email, FullName, Password) VALUES (?, ?, ?, ?)",
		req.Username, req.Email, req.FullName, hashedPassword,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	userID, err := result.LastInsertId()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	newUser := user{
		ID:       int(userID),
		Username: req.Username,
		Email:    req.Email,
		FullName: req.FullName,
	}

	c.JSON(http.StatusCreated, newUser)
}

// Login user and return JWT token
func login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Query user by username
	row := db.QueryRow("SELECT UserID, Username, Password FROM User WHERE Username = ?", req.Username)
	var userID int
	var username string
	var storedPassword string
	err := row.Scan(&userID, &username, &storedPassword)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Verify password
	if !verifyPassword(req.Password, storedPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Create JWT token
	expirationTime := time.Now().Add(24 * time.Hour) // Token expires in 24 hours
	claims := &CustomClaims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token"})
		return
	}

	c.JSON(http.StatusOK, loginResponse{
		Token:   tokenString,
		UserID:  userID,
		Message: "Login successful",
	})
}

// Hash password using bcrypt
func hashPassword(password string) (string, error) {
	// bcrypt.DefaultCost is 10, which provides a good balance between security and performance
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// Verify password against bcrypt hash
func verifyPassword(password, hash string) bool {
	// CompareHashAndPassword returns nil if the password matches the hash
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GAMES ENDPOINTS

func getGames(c *gin.Context) {
	rows, err := db.Query("SELECT g.GameID, g.Title, g.Platform, g.`Year`, g.`Condition`, g.OwnerID, c.CompanyID, c.CompanyName, c.YearFounded, c.Location FROM Games g JOIN Company c ON g.MadeBy = c.CompanyID")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var games []game
	for rows.Next() {
		var g game
		err := rows.Scan(&g.ID, &g.Title, &g.Platform, &g.Year, &g.Condition, &g.OwnerID, &g.MadeBy.ID, &g.MadeBy.CompanyName, &g.MadeBy.YearFounded, &g.MadeBy.Location)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		games = append(games, g)
	}

	if games == nil {
		games = []game{}
	}

	c.JSON(http.StatusOK, games)
}

// Get games owned by a specific user
func getGamesByUser(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	rows, err := db.Query("SELECT g.GameID, g.Title, g.Platform, g.`Year`, g.`Condition`, g.OwnerID, c.CompanyID, c.CompanyName, c.YearFounded, c.Location FROM Games g JOIN Company c ON g.MadeBy = c.CompanyID WHERE g.OwnerID = ?", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var games []game
	for rows.Next() {
		var g game
		err := rows.Scan(&g.ID, &g.Title, &g.Platform, &g.Year, &g.Condition, &g.OwnerID, &g.MadeBy.ID, &g.MadeBy.CompanyName, &g.MadeBy.YearFounded, &g.MadeBy.Location)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		games = append(games, g)
	}

	if games == nil {
		games = []game{}
	}

	c.JSON(http.StatusOK, games)
}

func addGame(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var raw []byte
	var err error
	raw, err = c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Try to unmarshal as a single game
	var newGame game
	if err := json.Unmarshal(raw, &newGame); err == nil && newGame.Title != "" {
		newGame.OwnerID = userID.(int)
		result, err := db.Exec(
			"INSERT INTO Games (Title, Platform, `Year`, `Condition`, MadeBy, OwnerID) VALUES (?, ?, ?, ?, ?, ?)",
			newGame.Title, newGame.Platform, newGame.Year, newGame.Condition, newGame.MadeBy.ID, newGame.OwnerID,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		id, err := result.LastInsertId()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		newGame.ID = int(id)
		c.JSON(http.StatusCreated, newGame)
		return
	}

	// Try to unmarshal as an array of games
	var newGames []game
	if err := json.Unmarshal(raw, &newGames); err == nil {
		var createdGames []game
		for _, ng := range newGames {
			ng.OwnerID = userID.(int)
			result, err := db.Exec(
				"INSERT INTO Games (Title, Platform, `Year`, `Condition`, MadeBy, OwnerID) VALUES (?, ?, ?, ?, ?, ?)",
				ng.Title, ng.Platform, ng.Year, ng.Condition, ng.MadeBy.ID, ng.OwnerID,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			id, err := result.LastInsertId()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			ng.ID = int(id)
			createdGames = append(createdGames, ng)
		}
		c.JSON(http.StatusCreated, createdGames)
		return
	}

	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format: expected game object or array of games"})
}

func replaceGame(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Check if user owns this game
	row := db.QueryRow("SELECT OwnerID FROM Games WHERE GameID = ?", id)
	var ownerID int
	err = row.Scan(&ownerID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
		return
	}

	if ownerID != userID.(int) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only modify your own games"})
		return
	}

	var newGame game
	if err := c.ShouldBindJSON(&newGame); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err = db.Exec(
		"UPDATE Games SET Title = ?, Platform = ?, `Year` = ?, `Condition` = ?, MadeBy = ? WHERE GameID = ?",
		newGame.Title, newGame.Platform, newGame.Year, newGame.Condition, newGame.MadeBy.ID, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Fetch and return the updated game
	row = db.QueryRow("SELECT g.GameID, g.Title, g.Platform, g.`Year`, g.`Condition`, g.OwnerID, c.CompanyID, c.CompanyName, c.YearFounded, c.Location FROM Games g JOIN Company c ON g.MadeBy = c.CompanyID WHERE g.GameID = ?", id)

	var game game
	err = row.Scan(&game.ID, &game.Title, &game.Platform, &game.Year, &game.Condition, &game.OwnerID, &game.MadeBy.ID, &game.MadeBy.CompanyName, &game.MadeBy.YearFounded, &game.MadeBy.Location)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
		return
	}

	c.JSON(http.StatusOK, game)
}

func updateGame(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Check if user owns this game
	row := db.QueryRow("SELECT OwnerID FROM Games WHERE GameID = ?", id)
	var ownerID int
	err = row.Scan(&ownerID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
		return
	}

	if ownerID != userID.(int) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only modify your own games"})
		return
	}

	var update gameUpdate
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build dynamic update query
	query := "UPDATE Games SET "
	args := []interface{}{}

	if update.Title != "" {
		query += "Title = ?, "
		args = append(args, update.Title)
	}
	if update.Platform != "" {
		query += "Platform = ?, "
		args = append(args, update.Platform)
	}
	if update.Year != 0 {
		query += "`Year` = ?, "
		args = append(args, update.Year)
	}
	if update.Condition != "" {
		query += "`Condition` = ?, "
		args = append(args, update.Condition)
	}
	if update.MadeBy.ID != 0 {
		query += "MadeBy = ?, "
		args = append(args, update.MadeBy.ID)
	}

	// Remove trailing comma and space
	query = query[:len(query)-2]
	query += " WHERE GameID = ?"
	args = append(args, id)

	_, err = db.Exec(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Fetch and return the updated game
	row = db.QueryRow("SELECT g.GameID, g.Title, g.Platform, g.`Year`, g.`Condition`, g.OwnerID, c.CompanyID, c.CompanyName, c.YearFounded, c.Location FROM Games g JOIN Company c ON g.MadeBy = c.CompanyID WHERE g.GameID = ?", id)

	var game game
	err = row.Scan(&game.ID, &game.Title, &game.Platform, &game.Year, &game.Condition, &game.OwnerID, &game.MadeBy.ID, &game.MadeBy.CompanyName, &game.MadeBy.YearFounded, &game.MadeBy.Location)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
		return
	}

	c.JSON(http.StatusOK, game)
}

func deleteGame(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Check if user owns this game
	row := db.QueryRow("SELECT OwnerID FROM Games WHERE GameID = ?", id)
	var ownerID int
	err = row.Scan(&ownerID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
		return
	}

	if ownerID != userID.(int) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only delete your own games"})
		return
	}

	result, err := db.Exec("DELETE FROM Games WHERE GameID = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
		return
	}

	c.Status(http.StatusNoContent)
}

// USERS ENDPOINTS

func getUsers(c *gin.Context) {
	rows, err := db.Query("SELECT UserID, Username, Email, FullName FROM User")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var users []user
	for rows.Next() {
		var u user
		err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FullName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		users = append(users, u)
	}

	if users == nil {
		users = []user{}
	}

	c.JSON(http.StatusOK, users)
}

func addUser(c *gin.Context) {
	var raw []byte
	var err error
	raw, err = c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Try to unmarshal as a single user
	var newUser user
	if err := json.Unmarshal(raw, &newUser); err == nil && newUser.Username != "" {
		result, err := db.Exec(
			"INSERT INTO User (Username, Email, FullName) VALUES (?, ?, ?)",
			newUser.Username, newUser.Email, newUser.FullName,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		id, err := result.LastInsertId()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		newUser.ID = int(id)
		c.JSON(http.StatusCreated, newUser)
		return
	}

	// Try to unmarshal as an array of users
	var newUsers []user
	if err := json.Unmarshal(raw, &newUsers); err == nil {
		var createdUsers []user
		for _, nu := range newUsers {
			result, err := db.Exec(
				"INSERT INTO User (Username, Email, FullName) VALUES (?, ?, ?)",
				nu.Username, nu.Email, nu.FullName,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			id, err := result.LastInsertId()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			nu.ID = int(id)
			createdUsers = append(createdUsers, nu)
		}
		c.JSON(http.StatusCreated, createdUsers)
		return
	}

	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format: expected user object or array of users"})
}

func replaceUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var newUser user
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err = db.Exec(
		"UPDATE User SET Username = ?, Email = ?, FullName = ? WHERE UserID = ?",
		newUser.Username, newUser.Email, newUser.FullName, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Fetch and return the updated user
	row := db.QueryRow("SELECT UserID, Username, Email, FullName FROM User WHERE UserID = ?", id)

	var returnUser user
	err = row.Scan(&returnUser.ID, &returnUser.Username, &returnUser.Email, &returnUser.FullName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
		return
	}

	c.JSON(http.StatusOK, returnUser)
}

func updateUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var update userUpdate
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build dynamic update query
	query := "UPDATE User SET "
	args := []interface{}{}

	if update.Username != "" {
		query += "Username = ?, "
		args = append(args, update.Username)
	}
	if update.Email != "" {
		query += "Email = ?, "
		args = append(args, update.Email)
	}
	if update.FullName != "" {
		query += "FullName = ?, "
		args = append(args, update.FullName)
	}

	// Remove trailing comma and space
	query = query[:len(query)-2]
	query += " WHERE UserID = ?"
	args = append(args, id)

	_, err = db.Exec(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Fetch and return the updated user
	row := db.QueryRow("SELECT UserID, Username, Email, FullName FROM User WHERE UserID = ?", id)

	var returnUser user
	err = row.Scan(&returnUser.ID, &returnUser.Username, &returnUser.Email, &returnUser.FullName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
		return
	}

	c.JSON(http.StatusOK, returnUser)
}

func deleteUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	result, err := db.Exec("DELETE FROM User WHERE UserID = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
		return
	}

	c.Status(http.StatusNoContent)
}

// TRADE OFFER ENDPOINTS

// Create a new trade offer
func createTradeOffer(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var req tradeOfferRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify target game exists and get owner
	targetRow := db.QueryRow("SELECT OwnerID FROM Games WHERE GameID = ?", req.TargetGameID)
	var targetOwnerID int
	err := targetRow.Scan(&targetOwnerID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Target game not found"})
		return
	}

	// Verify offered game exists and belongs to the user
	offeredRow := db.QueryRow("SELECT OwnerID FROM Games WHERE GameID = ?", req.OfferedGameID)
	var offeredOwnerID int
	err = offeredRow.Scan(&offeredOwnerID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Offered game not found"})
		return
	}

	if offeredOwnerID != userID.(int) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only offer games that you own"})
		return
	}

	if userID.(int) == targetOwnerID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot create a trade offer for your own game"})
		return
	}

	// Create the trade offer
	result, err := db.Exec(
		"INSERT INTO TradeOffer (CreatedByUserID, TargetGameID, OfferedGameID, Status) VALUES (?, ?, ?, 'pending')",
		userID.(int), req.TargetGameID, req.OfferedGameID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().Format("2006-01-02T15:04:05Z07:00")

	offer := tradeOffer{
		ID:              int(id),
		CreatedByUserID: userID.(int),
		TargetGameID:    req.TargetGameID,
		OfferedGameID:   req.OfferedGameID,
		Status:          "pending",
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	c.JSON(http.StatusCreated, offer)
}

// Get incoming trade offers for games owned by the authenticated user
func getIncomingOffers(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	query := `
		SELECT 
			t.OfferID, t.CreatedByUserID, t.TargetGameID, t.OfferedGameID, t.Status, DATE_FORMAT(t.CreatedAt, '%Y-%m-%dT%H:%i:%sZ'),
       DATE_FORMAT(t.UpdatedAt, '%Y-%m-%dT%H:%i:%sZ'),
			u.UserID, u.Username, u.Email, u.FullName,
			tg.GameID, tg.Title, tg.Platform, tg.` + "`Year`" + `, tg.` + "`Condition`" + `, tg.OwnerID, tc.CompanyID, tc.CompanyName, tc.YearFounded, tc.Location,
			og.GameID, og.Title, og.Platform, og.` + "`Year`" + `, og.` + "`Condition`" + `, og.OwnerID, oc.CompanyID, oc.CompanyName, oc.YearFounded, oc.Location
		FROM TradeOffer t
		JOIN User u ON t.CreatedByUserID = u.UserID
		JOIN Games tg ON t.TargetGameID = tg.GameID
		JOIN Company tc ON tg.MadeBy = tc.CompanyID
		JOIN Games og ON t.OfferedGameID = og.GameID
		JOIN Company oc ON og.MadeBy = oc.CompanyID
		WHERE tg.OwnerID = ?
		ORDER BY t.CreatedAt DESC
	`

	rows, err := db.Query(query, userID.(int))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var offers []tradeOfferResponse
	for rows.Next() {
		var offer tradeOfferResponse
		var createdAt, updatedAt string

		err := rows.Scan(
			&offer.ID, &offer.CreatedByUserID, &offer.TargetGameID, &offer.OfferedGameID, &offer.Status, &createdAt, &updatedAt,
			&offer.CreatedByUser.ID, &offer.CreatedByUser.Username, &offer.CreatedByUser.Email, &offer.CreatedByUser.FullName,
			&offer.TargetGame.ID, &offer.TargetGame.Title, &offer.TargetGame.Platform, &offer.TargetGame.Year, &offer.TargetGame.Condition, &offer.TargetGame.OwnerID, &offer.TargetGame.MadeBy.ID, &offer.TargetGame.MadeBy.CompanyName, &offer.TargetGame.MadeBy.YearFounded, &offer.TargetGame.MadeBy.Location,
			&offer.OfferedGame.ID, &offer.OfferedGame.Title, &offer.OfferedGame.Platform, &offer.OfferedGame.Year, &offer.OfferedGame.Condition, &offer.OfferedGame.OwnerID, &offer.OfferedGame.MadeBy.ID, &offer.OfferedGame.MadeBy.CompanyName, &offer.OfferedGame.MadeBy.YearFounded, &offer.OfferedGame.MadeBy.Location,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		offer.CreatedAt = createdAt
		offer.UpdatedAt = updatedAt
		offers = append(offers, offer)
	}

	if offers == nil {
		offers = []tradeOfferResponse{}
	}

	c.JSON(http.StatusOK, offers)
}

// Get outgoing trade offers created by the authenticated user
func getOutgoingOffers(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	query := `
		SELECT 
			t.OfferID, t.CreatedByUserID, t.TargetGameID, t.OfferedGameID, t.Status, DATE_FORMAT(t.CreatedAt, '%Y-%m-%dT%H:%i:%sZ'),
       DATE_FORMAT(t.UpdatedAt, '%Y-%m-%dT%H:%i:%sZ'),
			u.UserID, u.Username, u.Email, u.FullName,
			tg.GameID, tg.Title, tg.Platform, tg.` + "`Year`" + `, tg.` + "`Condition`" + `, tg.OwnerID, tc.CompanyID, tc.CompanyName, tc.YearFounded, tc.Location,
			og.GameID, og.Title, og.Platform, og.` + "`Year`" + `, og.` + "`Condition`" + `, og.OwnerID, oc.CompanyID, oc.CompanyName, oc.YearFounded, oc.Location
		FROM TradeOffer t
		JOIN User u ON t.CreatedByUserID = u.UserID
		JOIN Games tg ON t.TargetGameID = tg.GameID
		JOIN Company tc ON tg.MadeBy = tc.CompanyID
		JOIN Games og ON t.OfferedGameID = og.GameID
		JOIN Company oc ON og.MadeBy = oc.CompanyID
		WHERE t.CreatedByUserID = ?
		ORDER BY t.CreatedAt DESC
	`

	rows, err := db.Query(query, userID.(int))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var offers []tradeOfferResponse
	for rows.Next() {
		var offer tradeOfferResponse
		var createdAt, updatedAt string

		err := rows.Scan(
			&offer.ID, &offer.CreatedByUserID, &offer.TargetGameID, &offer.OfferedGameID, &offer.Status, &createdAt, &updatedAt,
			&offer.CreatedByUser.ID, &offer.CreatedByUser.Username, &offer.CreatedByUser.Email, &offer.CreatedByUser.FullName,
			&offer.TargetGame.ID, &offer.TargetGame.Title, &offer.TargetGame.Platform, &offer.TargetGame.Year, &offer.TargetGame.Condition, &offer.TargetGame.OwnerID, &offer.TargetGame.MadeBy.ID, &offer.TargetGame.MadeBy.CompanyName, &offer.TargetGame.MadeBy.YearFounded, &offer.TargetGame.MadeBy.Location,
			&offer.OfferedGame.ID, &offer.OfferedGame.Title, &offer.OfferedGame.Platform, &offer.OfferedGame.Year, &offer.OfferedGame.Condition, &offer.OfferedGame.OwnerID, &offer.OfferedGame.MadeBy.ID, &offer.OfferedGame.MadeBy.CompanyName, &offer.OfferedGame.MadeBy.YearFounded, &offer.OfferedGame.MadeBy.Location,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		offer.CreatedAt = createdAt
		offer.UpdatedAt = updatedAt
		offers = append(offers, offer)
	}

	if offers == nil {
		offers = []tradeOfferResponse{}
	}

	c.JSON(http.StatusOK, offers)
}

// Update trade offer status (accept or reject)
func updateTradeOfferStatus(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	offerID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid offer ID"})
		return
	}

	var req statusUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Status != "accepted" && req.Status != "rejected" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Status must be 'accepted' or 'rejected'"})
		return
	}

	// Get the offer and verify the user owns the target game
	row := db.QueryRow("SELECT t.TargetGameID, tg.OwnerID FROM TradeOffer t JOIN Games tg ON t.TargetGameID = tg.GameID WHERE t.OfferID = ?", offerID)
	var targetGameID int
	var gameOwnerID int
	err = row.Scan(&targetGameID, &gameOwnerID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Trade offer not found"})
		return
	}

	if gameOwnerID != userID.(int) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only respond to offers for your own games"})
		return
	}

	// Update the trade offer status
	_, err = db.Exec("UPDATE TradeOffer SET Status = ? WHERE OfferID = ?", req.Status, offerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Trade offer " + req.Status})
}

func main() {
	router := gin.Default()

	// Authentication endpoints
	router.POST("/register", register)
	router.POST("/login", login)

	// Games endpoints (public - no auth)
	router.GET("/games", getGames)
	router.GET("/users/:userId/games", getGamesByUser)

	// Games endpoints (protected - require auth)
	router.POST("/games", authMiddleware(), addGame)
	router.PUT("/games/:id", authMiddleware(), replaceGame)
	router.PATCH("/games/:id", authMiddleware(), updateGame)
	router.DELETE("/games/:id", authMiddleware(), deleteGame)

	// Users endpoints (public)
	router.GET("/users", getUsers)
	router.POST("/users", addUser)
	router.PUT("/users/:id", replaceUser)
	router.PATCH("/users/:id", updateUser)
	router.DELETE("/users/:id", deleteUser)

	// Trade offer endpoints (protected - require auth)
	router.POST("/trade-offers", authMiddleware(), createTradeOffer)
	router.GET("/trade-offers/incoming", authMiddleware(), getIncomingOffers)
	router.GET("/trade-offers/outgoing", authMiddleware(), getOutgoingOffers)
	router.PATCH("/trade-offers/:id/status", authMiddleware(), updateTradeOfferStatus)

	err := router.Run(":8080")
	if err != nil {
		return
	}
}
