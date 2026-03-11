package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func getCompanies(c *gin.Context) {
	rows, err := db.Query("SELECT CompanyID, CompanyName, YearFounded, Location FROM Company")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var companies []company
	for rows.Next() {
		var co company
		if err := rows.Scan(&co.ID, &co.CompanyName, &co.YearFounded, &co.Location); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		companies = append(companies, co)
	}
	if companies == nil {
		companies = []company{}
	}
	c.JSON(http.StatusOK, companies)
}
