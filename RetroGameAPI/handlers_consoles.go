package main

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func getConsoles(c *gin.Context) {
	rows, err := db.Query("SELECT" + consoleSelectCols + consoleJoin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var consoles []console
	for rows.Next() {
		con, err := scanConsole(rows)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		consoles = append(consoles, con)
	}
	if consoles == nil {
		consoles = []console{}
	}
	c.JSON(http.StatusOK, consoles)
}

func getConsole(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	row := db.QueryRow("SELECT"+consoleSelectCols+consoleJoin+" WHERE con.ConsoleID = ?", id)
	con, err := scanConsole(row)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "console not found"})
		return
	}
	c.JSON(http.StatusOK, con)
}

func addConsole(c *gin.Context) {
	var newConsole console
	if err := c.ShouldBindJSON(&newConsole); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify manufacturer exists
	var mfrCheck int
	if err := db.QueryRow("SELECT CompanyID FROM Company WHERE CompanyID = ?", newConsole.Manufacturer.ID).Scan(&mfrCheck); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "manufacturer company not found"})
		return
	}

	result, err := db.Exec(
		"INSERT INTO Console (Name, ManufacturerID, ReleaseYear, Region) VALUES (?, ?, ?, ?)",
		newConsole.Name, newConsole.Manufacturer.ID, newConsole.ReleaseYear, newConsole.Region,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	id, _ := result.LastInsertId()

	row := db.QueryRow("SELECT"+consoleSelectCols+consoleJoin+" WHERE con.ConsoleID = ?", id)
	created, err := scanConsole(row)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, created)
}

func replaceConsole(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var req console
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := db.Exec(
		"UPDATE Console SET Name = ?, ManufacturerID = ?, ReleaseYear = ?, Region = ? WHERE ConsoleID = ?",
		req.Name, req.Manufacturer.ID, req.ReleaseYear, req.Region, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "console not found"})
		return
	}

	row := db.QueryRow("SELECT"+consoleSelectCols+consoleJoin+" WHERE con.ConsoleID = ?", id)
	updated, err := scanConsole(row)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, updated)
}

func updateConsole(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var upd consoleUpdate
	if err := c.ShouldBindJSON(&upd); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := "UPDATE Console SET "
	args := []interface{}{}

	if upd.Name != "" {
		query += "Name = ?, "
		args = append(args, upd.Name)
	}
	if upd.Manufacturer.ID != 0 {
		query += "ManufacturerID = ?, "
		args = append(args, upd.Manufacturer.ID)
	}
	if upd.ReleaseYear != 0 {
		query += "ReleaseYear = ?, "
		args = append(args, upd.ReleaseYear)
	}
	if upd.Region != "" {
		query += "Region = ?, "
		args = append(args, upd.Region)
	}

	if len(args) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	query = query[:len(query)-2] + " WHERE ConsoleID = ?"
	args = append(args, id)

	if _, err = db.Exec(query, args...); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	row := db.QueryRow("SELECT"+consoleSelectCols+consoleJoin+" WHERE con.ConsoleID = ?", id)
	updated, err := scanConsole(row)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "console not found"})
		return
	}
	c.JSON(http.StatusOK, updated)
}

func deleteConsole(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	// Guard: reject if any game still references this console
	var refCount int
	db.QueryRow("SELECT COUNT(*) FROM Games WHERE ConsoleID = ?", id).Scan(&refCount)
	if refCount > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "cannot delete console: games are still associated with it"})
		return
	}

	res, err := db.Exec("DELETE FROM Console WHERE ConsoleID = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "console not found"})
		return
	}
	c.Status(http.StatusNoContent)
}
