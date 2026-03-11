package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func getGames(c *gin.Context) {
	rows, err := db.Query("SELECT" + gameSelectCols + gameJoin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var games []game
	for rows.Next() {
		g, err := scanGame(rows)
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

func getGamesByUser(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	rows, err := db.Query("SELECT"+gameSelectCols+gameJoin+" WHERE g.OwnerID = ?", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var games []game
	for rows.Next() {
		g, err := scanGame(rows)
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

	raw, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// insertOne is a small closure to avoid repeating the INSERT logic
	insertOne := func(ng game) (game, error) {
		ng.OwnerID = userID.(int)
		result, err := db.Exec(
			"INSERT INTO Games (Title, ConsoleID, `Year`, `Condition`, MadeBy, OwnerID) VALUES (?, ?, ?, ?, ?, ?)",
			ng.Title, ng.Console.ID, ng.Year, ng.Condition, ng.MadeBy.ID, ng.OwnerID,
		)
		if err != nil {
			return game{}, err
		}
		id, _ := result.LastInsertId()
		row := db.QueryRow("SELECT"+gameSelectCols+gameJoin+" WHERE g.GameID = ?", id)
		return scanGame(row)
	}

	// Try single game first
	var newGame game
	if err := json.Unmarshal(raw, &newGame); err == nil && newGame.Title != "" {
		created, err := insertOne(newGame)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		GameCreated.Inc()
		c.JSON(http.StatusCreated, created)
		return
	}

	// Try array of games
	var newGames []game
	if err := json.Unmarshal(raw, &newGames); err == nil {
		var createdGames []game
		for _, ng := range newGames {
			created, err := insertOne(ng)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			createdGames = append(createdGames, created)
		}
		GameCreated.Add(float64(len(createdGames)))
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

	var ownerID int
	if err = db.QueryRow("SELECT OwnerID FROM Games WHERE GameID = ?", id).Scan(&ownerID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
		return
	}
	if ownerID != userID.(int) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only modify your own games"})
		return
	}

	var req game
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err = db.Exec(
		"UPDATE Games SET Title = ?, ConsoleID = ?, `Year` = ?, `Condition` = ?, MadeBy = ? WHERE GameID = ?",
		req.Title, req.Console.ID, req.Year, req.Condition, req.MadeBy.ID, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	row := db.QueryRow("SELECT"+gameSelectCols+gameJoin+" WHERE g.GameID = ?", id)
	updated, err := scanGame(row)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
		return
	}
	c.JSON(http.StatusOK, updated)
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

	var ownerID int
	if err = db.QueryRow("SELECT OwnerID FROM Games WHERE GameID = ?", id).Scan(&ownerID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
		return
	}
	if ownerID != userID.(int) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only modify your own games"})
		return
	}

	var upd gameUpdate
	if err := c.ShouldBindJSON(&upd); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := "UPDATE Games SET "
	args := []interface{}{}

	if upd.Title != "" {
		query += "Title = ?, "
		args = append(args, upd.Title)
	}
	if upd.Console.ID != 0 {
		query += "ConsoleID = ?, "
		args = append(args, upd.Console.ID)
	}
	if upd.Year != 0 {
		query += "`Year` = ?, "
		args = append(args, upd.Year)
	}
	if upd.Condition != "" {
		query += "`Condition` = ?, "
		args = append(args, upd.Condition)
	}
	if upd.MadeBy.ID != 0 {
		query += "MadeBy = ?, "
		args = append(args, upd.MadeBy.ID)
	}

	if len(args) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	query = query[:len(query)-2] + " WHERE GameID = ?"
	args = append(args, id)

	if _, err = db.Exec(query, args...); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	row := db.QueryRow("SELECT"+gameSelectCols+gameJoin+" WHERE g.GameID = ?", id)
	updated, err := scanGame(row)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
		return
	}
	c.JSON(http.StatusOK, updated)
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

	var ownerID int
	if err = db.QueryRow("SELECT OwnerID FROM Games WHERE GameID = ?", id).Scan(&ownerID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
		return
	}
	if ownerID != userID.(int) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only delete your own games"})
		return
	}

	res, err := db.Exec("DELETE FROM Games WHERE GameID = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "game not found"})
		return
	}
	c.Status(http.StatusNoContent)
}
