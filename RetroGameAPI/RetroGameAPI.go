package main

import (
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
	var newGame game
	if err := c.ShouldBindJSON(&newGame); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	newGame.ID = nextGameID
	nextGameID++
	games = append(games, newGame)
	c.JSON(http.StatusCreated, newGame)
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
	var newUser user
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	newUser.ID = nextUserID
	nextUserID++
	users = append(users, newUser)
	c.JSON(http.StatusCreated, newUser)
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
	//router.PUT("/games/:id", replaceGame)
	//router.PATCH("/games/:id", updateGame)
	router.DELETE("/games/:id", deleteGame)

	router.POST("/users", addUser)
	//router.PUT("/users/:id", replaceUser)
	//router.PATCH("/users/:id", updateUser)
	router.DELETE("/users/:id", deleteUser)

	router.Run("localhost:8080")
}
