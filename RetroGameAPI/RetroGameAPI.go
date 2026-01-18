package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type game struct {
	ID        int     `json:"id"`
	Title     string  `json:"title" binding:"required"`
	Platform  string  `json:"platform" binding:"required"`
	Year      int     `json:"year"`
	Condition string  `json:"condition"`
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

var games = []game{
	{
		ID:        1,
		Title:     "Super Mario World",
		Platform:  "SNES",
		Year:      1990,
		Condition: "Mint",
		MadeBy: company{
			ID:          50,
			CompanyName: "Nintendo",
			YearFounded: 1889,
			Location:    "Kyoto, Japan",
		},
	},
}

var users = []user{
	{
		ID:       101,
		Username: "johndoe",
		Email:    "john.doe@example.com",
		FullName: "John Doe",
	},
}

var nextGameID = 2
var nextUserID = 102

func getGames(c *gin.Context) {
	c.JSON(http.StatusOK, games)
}

func addGame(c *gin.Context) {
	fmt.Println("addGame called")
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
		newGame.ID = nextGameID
		nextGameID++
		games = append(games, newGame)
		c.JSON(http.StatusCreated, newGame)
		return
	}

	// Try to unmarshal as an array of games
	var newGames []game
	if err := json.Unmarshal(raw, &newGames); err == nil {
		for i := range newGames {
			newGames[i].ID = nextGameID
			nextGameID++
			games = append(games, newGames[i])
		}
		c.JSON(http.StatusCreated, newGames)
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
	var newGame game
	if err := c.ShouldBindJSON(&newGame); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	for i, g := range games {
		if g.ID == id {
			newGame.ID = id
			games[i] = newGame
			c.JSON(http.StatusOK, games[i])
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
}

func updateGame(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	var update gameUpdate
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	for i, g := range games {
		if g.ID == id {
			if update.Title != "" {
				games[i].Title = update.Title
			}
			if update.Platform != "" {
				games[i].Platform = update.Platform
			}
			if update.Year != 0 {
				games[i].Year = update.Year
			}
			if update.Condition != "" {
				games[i].Condition = update.Condition
			}
			if update.MadeBy.CompanyName != "" {
				games[i].MadeBy.CompanyName = update.MadeBy.CompanyName
			}
			if update.MadeBy.YearFounded != 0 {
				games[i].MadeBy.YearFounded = update.MadeBy.YearFounded
			}
			if update.MadeBy.Location != "" {
				games[i].MadeBy.Location = update.MadeBy.Location
			}
			c.JSON(http.StatusOK, games[i])
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
}

func deleteGame(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	for i, g := range games {
		if g.ID == id {
			games = append(games[:i], games[i+1:]...)
			c.Status(http.StatusNoContent)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
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
		newUser.ID = nextUserID
		nextUserID++
		users = append(users, newUser)
		c.JSON(http.StatusCreated, newUser)
		return
	}

	// Try to unmarshal as an array of users
	var newUsers []user
	if err := json.Unmarshal(raw, &newUsers); err == nil {
		for i := range newUsers {
			newUsers[i].ID = nextUserID
			nextUserID++
			users = append(users, newUsers[i])
		}
		c.JSON(http.StatusCreated, newUsers)
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
	for i, u := range users {
		if u.ID == id {
			newUser.ID = id
			users[i] = newUser
			c.JSON(http.StatusOK, users[i])
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
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
	for i, u := range users {
		if u.ID == id {
			if update.Username != "" {
				users[i].Username = update.Username
			}
			if update.Email != "" {
				users[i].Email = update.Email
			}
			if update.FullName != "" {
				users[i].FullName = update.FullName
			}
			c.JSON(http.StatusOK, users[i])
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
}

func deleteUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	for i, u := range users {
		if u.ID == id {
			users = append(users[:i], users[i+1:]...)
			c.Status(http.StatusNoContent)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
}

func main() {
	router := gin.Default()
	router.GET("/games", getGames)
	router.POST("/games", addGame)
	router.PUT("/games/:id", replaceGame)
	router.PATCH("/games/:id", updateGame)
	router.DELETE("/games/:id", deleteGame)

	router.POST("/users", addUser)
	router.PUT("/users/:id", replaceUser)
	router.PATCH("/users/:id", updateUser)
	router.DELETE("/users/:id", deleteUser)

	err := router.Run("localhost:8080")
	if err != nil {
		return
	}
}
