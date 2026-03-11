package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"strconv"

	"github.com/gin-gonic/gin"
)

func getUsers(c *gin.Context) {
	rows, err := db.Query("SELECT UserID, Username, Email, FullName, Address FROM User")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var users []user
	for rows.Next() {
		var u user
		err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FullName, &u.Address)
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
			"INSERT INTO User (Username, Email, FullName, Address) VALUES (?, ?, ?, ?)",
			newUser.Username, newUser.Email, newUser.FullName, newUser.Address,
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
				"INSERT INTO User (Username, Email, FullName, Address) VALUES (?, ?, ?, ?)",
				nu.Username, nu.Email, nu.FullName, nu.Address,
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
		"UPDATE User SET Username = ?, Email = ?, FullName = ?, Address = ? WHERE UserID = ?",
		newUser.Username, newUser.Email, newUser.FullName, newUser.Address, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Fetch and return the updated user
	row := db.QueryRow("SELECT UserID, Username, Email, FullName, Address FROM User WHERE UserID = ?", id)

	var returnUser user
	err = row.Scan(&returnUser.ID, &returnUser.Username, &returnUser.Email, &returnUser.FullName, &returnUser.Address)
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
	if update.Address != "" {
		query += "Address = ?, "
		args = append(args, update.Address)
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
	row := db.QueryRow("SELECT UserID, Username, Email, FullName, Address FROM User WHERE UserID = ?", id)

	var returnUser user
	err = row.Scan(&returnUser.ID, &returnUser.Username, &returnUser.Email, &returnUser.FullName, &returnUser.Address)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
		return
	}

	c.JSON(http.StatusOK, returnUser)
}

func updatePassword(c *gin.Context) {
	// 1. Get the authenticated userID from the context (set by authMiddleware)
	authenticatedUserID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// 2. Get the target ID from the URL parameter
	targetID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	// 3. SECURITY CHECK: Compare the IDs
	// This ensures a user can only change THEIR OWN password.
	if authenticatedUserID.(int) != targetID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to change this user's password"})
		return
	}

	// 4. Bind the request body
	var req passwordUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 5. Look up the user in the database to get their stored password hash and email
	var storedPassword string
	var email string
	row := db.QueryRow("SELECT Password, Email FROM User WHERE UserID = ?", targetID)
	err = row.Scan(&storedPassword, &email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "user not found"})
		return
	}

	// 6. Verify the current password is correct
	// This is important because it ensures the person requesting the change
	// actually knows the current credentials, preventing session hijacking attacks.
	if !verifyPassword(req.CurrentPassword, storedPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect"})
		return
	}

	// 7. Hash the new password
	hashedPassword, err := hashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	// 8. Update the database
	_, err = db.Exec("UPDATE User SET Password = ? WHERE UserID = ?", hashedPassword, targetID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 9. Send the notification
	notification := EmailNotification{
		EventType:  PasswordChanged,
		Recipient1: mail.Address{Address: email},
		Subject:    "Security Alert: Password Changed",
		Body:       "The password for your RetroGameAPI account has been successfully updated.",
	}
	if err := publishEmailNotification(notification); err != nil {
		fmt.Println("Kafka publish error:", err)
	} // Log error if needed, but don't fail the request

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
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
