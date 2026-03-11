package main

import (
	"github.com/golang-jwt/jwt/v5"
)

type game struct {
	ID        int     `json:"id"`
	Title     string  `json:"title" binding:"required"`
	Console   console `json:"console" binding:"required"`
	Year      int     `json:"year"`
	Condition string  `json:"condition"`
	OwnerID   int     `json:"ownerId"`
	MadeBy    company `json:"madeBy" binding:"required"`
}

type gameUpdate struct {
	ID        int     `json:"id"`
	Title     string  `json:"title"`
	Console   console `json:"console"`
	Year      int     `json:"year"`
	Condition string  `json:"condition"`
	MadeBy    company `json:"madeBy"`
}

type user struct {
	ID       int    `json:"id"`
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
	FullName string `json:"fullName"`
	Address  string `json:"address"`
}

type userUpdate struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"fullName"`
	Address  string `json:"address"`
}

type company struct {
	ID          int    `json:"id"`
	CompanyName string `json:"companyName"`
	YearFounded int    `json:"yearFounded"`
	Location    string `json:"location"`
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

type console struct {
	ID           int     `json:"id"`
	Name         string  `json:"name" binding:"required"`
	Manufacturer company `json:"manufacturer" binding:"required"`
	ReleaseYear  int     `json:"releaseYear" binding:"required"`
	Region       string  `json:"region" binding:"required"`
}

type consoleUpdate struct {
	Name         string  `json:"name"`
	Manufacturer company `json:"manufacturer"`
	ReleaseYear  int     `json:"releaseYear"`
	Region       string  `json:"region"`
}

type tradeOfferRequest struct {
	TargetGameID  int `json:"targetGameId" binding:"required"`
	OfferedGameID int `json:"offeredGameId" binding:"required"`
}

type passwordUpdateRequest struct {
	CurrentPassword string `json:"currentPassword" binding:"required"`
	NewPassword     string `json:"newPassword" binding:"required"`
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
	Address  string `json:"address"`
}

type CustomClaims struct {
	UserID   int    `json:"userId"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}
