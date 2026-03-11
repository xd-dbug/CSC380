package main

import (
	"fmt"
	"net/http"
	"net/mail"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

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

	offereeRow := db.QueryRow("SELECT Email FROM User WHERE UserID = ?", targetOwnerID)
	offerorRow := db.QueryRow("SELECT Email FROM User WHERE UserID = ?", userID)

	var offereeEmail string
	var offerorEmail string

	err = offereeRow.Scan(&offereeEmail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	err = offerorRow.Scan(&offerorEmail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	email := EmailNotification{
		EventType:  OfferCreated,
		Recipient1: mail.Address{Address: offereeEmail},
		Recipient2: &mail.Address{Address: offerorEmail},
		Subject:    "Security Alert: Trade offer created",
		Body:       "The trade offer has been successfully created",
	}

	err = publishEmailNotification(email)
	if err != nil {
		return
	}
	tradeOfferCreated.Inc()
	c.JSON(http.StatusCreated, offer)
}

func getIncomingOffers(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	query := fmt.Sprintf(`
		SELECT
			t.OfferID, t.CreatedByUserID, t.TargetGameID, t.OfferedGameID, t.Status,
			DATE_FORMAT(t.CreatedAt, '%%Y-%%m-%%dT%%H:%%i:%%sZ'),
			DATE_FORMAT(t.UpdatedAt, '%%Y-%%m-%%dT%%H:%%i:%%sZ'),
			u.UserID, u.Username, u.Email, u.FullName,
			%s,
			%s
		FROM TradeOffer t
		JOIN User u ON t.CreatedByUserID = u.UserID
		JOIN Games tg ON t.TargetGameID = tg.GameID
		JOIN Console tcon ON tg.ConsoleID = tcon.ConsoleID
		JOIN Company tmfr ON tcon.ManufacturerID = tmfr.CompanyID
		JOIN Company tpub ON tg.MadeBy = tpub.CompanyID
		JOIN Games og ON t.OfferedGameID = og.GameID
		JOIN Console ocon ON og.ConsoleID = ocon.ConsoleID
		JOIN Company omfr ON ocon.ManufacturerID = omfr.CompanyID
		JOIN Company opub ON og.MadeBy = opub.CompanyID
		WHERE tg.OwnerID = ?
		ORDER BY t.CreatedAt DESC`,
		gameOfferCols("tg", "tcon", "tmfr", "tpub"),
		gameOfferCols("og", "ocon", "omfr", "opub"),
	)

	rows, err := db.Query(query, userID.(int))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	offers, err := scanTradeOfferRows(rows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, offers)
}

func getOutgoingOffers(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	query := fmt.Sprintf(`
		SELECT
			t.OfferID, t.CreatedByUserID, t.TargetGameID, t.OfferedGameID, t.Status,
			DATE_FORMAT(t.CreatedAt, '%%Y-%%m-%%dT%%H:%%i:%%sZ'),
			DATE_FORMAT(t.UpdatedAt, '%%Y-%%m-%%dT%%H:%%i:%%sZ'),
			u.UserID, u.Username, u.Email, u.FullName,
			%s,
			%s
		FROM TradeOffer t
		JOIN User u ON t.CreatedByUserID = u.UserID
		JOIN Games tg ON t.TargetGameID = tg.GameID
		JOIN Console tcon ON tg.ConsoleID = tcon.ConsoleID
		JOIN Company tmfr ON tcon.ManufacturerID = tmfr.CompanyID
		JOIN Company tpub ON tg.MadeBy = tpub.CompanyID
		JOIN Games og ON t.OfferedGameID = og.GameID
		JOIN Console ocon ON og.ConsoleID = ocon.ConsoleID
		JOIN Company omfr ON ocon.ManufacturerID = omfr.CompanyID
		JOIN Company opub ON og.MadeBy = opub.CompanyID
		WHERE t.CreatedByUserID = ?
		ORDER BY t.CreatedAt DESC`,
		gameOfferCols("tg", "tcon", "tmfr", "tpub"),
		gameOfferCols("og", "ocon", "omfr", "opub"),
	)

	rows, err := db.Query(query, userID.(int))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	offers, err := scanTradeOfferRows(rows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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
	row := db.QueryRow("SELECT t.TargetGameID, tg.OwnerID, t.OfferedGameID, t.CreatedByUserID, offeror.Email, offeree.Email FROM TradeOffer t JOIN Games tg ON t.TargetGameID = tg.GameID JOIN User offeror ON t.CreatedByUserID = offeror.UserID JOIN User offeree ON tg.OwnerID = offeree.UserID WHERE t.OfferID = ?", offerID)
	var targetGameID int
	var gameOwnerID int
	var offereeEmail string
	var offerorEmail string
	var offeredGameID int
	var createdByUserID int
	err = row.Scan(&targetGameID, &gameOwnerID, &offeredGameID, &createdByUserID, &offerorEmail, &offereeEmail)
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

	if req.Status == "accepted" {
		_, err = db.Exec("UPDATE Games SET OwnerID = ? WHERE GameID = ?", createdByUserID, targetGameID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		_, err = db.Exec("UPDATE Games SET OwnerID = ? WHERE GameID = ?", userID.(int), offeredGameID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	email := EmailNotification{}

	if req.Status == "accepted" {
		email = EmailNotification{
			EventType:  OfferAccepted,
			Recipient1: mail.Address{Address: offerorEmail},
			Recipient2: &mail.Address{Address: offereeEmail},
			Subject:    "Offer Accepted",
			Body:       fmt.Sprintf("Trade offer #%d has been accepted.", offerID),
		}
	} else {
		email = EmailNotification{
			EventType:  OfferRejected,
			Recipient1: mail.Address{Address: offereeEmail},
			Recipient2: &mail.Address{Address: offerorEmail},
			Subject:    "Offer Rejected",
			Body:       fmt.Sprintf("Trade offer #%d has been rejected.", offerID),
		}
	}

	if err := publishEmailNotification(email); err != nil {
		fmt.Println("Kafka publish error:", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Trade offer " + req.Status})
}
