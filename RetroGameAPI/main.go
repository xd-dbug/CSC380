package main

import (
	"database/sql"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/segmentio/kafka-go"
)

var db *sql.DB
var jwtSecret []byte
var kafkaWriter *kafka.Writer

var tradeOfferCreated = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "retrogames_trade_offer_created_total",
	Help: "The total number of trade offers created",
})
var UserCreated = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "retrogames_user_created_total",
	Help: "The total number of user created",
})
var GameCreated = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "retrogames_game_created_total",
	Help: "The total number of game created",
})

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

	dsn := dbUser + ":" + dbPassword + "@tcp(" + dbHost + ":" + dbPort + ")/" + dbName
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}

	prometheus.MustRegister(tradeOfferCreated)
	prometheus.MustRegister(UserCreated)
	prometheus.MustRegister(GameCreated)
}

func main() {
	router := gin.Default()

	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

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
	router.PATCH("/users/:id/password", authMiddleware(), updatePassword)
	router.DELETE("/users/:id", deleteUser)

	// Trade offer endpoints (protected - require auth)
	router.POST("/trade-offers", authMiddleware(), createTradeOffer)
	router.GET("/trade-offers/incoming", authMiddleware(), getIncomingOffers)
	router.GET("/trade-offers/outgoing", authMiddleware(), getOutgoingOffers)
	router.PATCH("/trade-offers/:id/status", authMiddleware(), updateTradeOfferStatus)

	// Console endpoints
	router.GET("/consoles", getConsoles)
	router.GET("/consoles/:id", getConsole)
	router.POST("/consoles", authMiddleware(), addConsole)
	router.PUT("/consoles/:id", authMiddleware(), replaceConsole)
	router.PATCH("/consoles/:id", authMiddleware(), updateConsole)
	router.DELETE("/consoles/:id", authMiddleware(), deleteConsole)

	router.GET("/companies", getCompanies)

	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	err := router.Run(":8080")
	if err != nil {
		return
	}
}
